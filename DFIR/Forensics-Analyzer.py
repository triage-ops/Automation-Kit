#!/usr/bin/env python3

print('''

8"""""8                                                                                                    
8      e  e     eeee eeeee eeee eeee    e  eeeee    eeeee eeeee e  e     e        eeeee eeeee eeeee eeeee 
8eeeee 8  8     8    8   8 8  8 8       8  8   "    8   "   8   8  8     8        8   8 8   8   8   8   8 
    88 8e 8e    8eee 8e  8 8e   8eee    8e 8eeee    8eeee   8e  8e 8e    8e       8e  8 8eee8   8e  8eee8 
e   88 88 88    88   88  8 88   88      88    88       88   88  88 88    88       88  8 88  8   88  88  8 
8eee88 88 88eee 88ee 88  8 88e8 88ee    88 8ee88    8ee88   88  88 88eee 88eee    88ee8 88  8   88  88  8 
                                                                                                          
''')

import os
import sys
import hashlib
import subprocess
import shutil
import re
import struct
import math
import json
import mmap
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools

VERSION = "3.0"
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10 GB safety limit

# === COLORS ===
COLORS = {
    'HEADER': '\033[95m',
    'BLUE':   '\033[94m',
    'CYAN':   '\033[96m',
    'GREEN':  '\033[92m',
    'WARNING':'\033[93m',
    'FAIL':   '\033[91m',
    'ENDC':   '\033[0m',
    'BOLD':   '\033[1m',
    'YELLOW': '\033[33m',
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['ENDC']}")

# === DEPENDENCY CHECK ===
REQUIRED_DEPS = {
    'file':    'file',
    'strings': 'binutils',
}

OPTIONAL_DEPS = {
    'binwalk':    'binwalk',
    'foremost':   'foremost',
    'exiftool':   'libimage-exiftool-perl',
    'volatility': 'volatility',
    'vol.py':     'volatility3',
    'yara':       'yara',
    'readelf':    'binutils',
    'objdump':    'binutils',
}

def check_dependencies():
    missing_required = []
    missing_optional = []

    log("[*] Checking dependencies...", "BLUE")

    for tool, package in REQUIRED_DEPS.items():
        if not shutil.which(tool):
            missing_required.append(f"{tool} ({package})")

    for tool, package in OPTIONAL_DEPS.items():
        if not shutil.which(tool):
            missing_optional.append(f"{tool} ({package})")

    if not missing_required and not missing_optional:
        log("[✓] All dependencies satisfied!\n", "GREEN")
        return

    if missing_required:
        log("[✗] MISSING REQUIRED DEPENDENCIES:", "FAIL")
        for dep in missing_required:
            print(f"    {dep}")
        packages = list(set(REQUIRED_DEPS[tool.split()[0]] for tool in missing_required))
        print(f"\n{COLORS['WARNING']}Install with:{COLORS['ENDC']}")
        print(f"    {COLORS['BOLD']}sudo apt install {' '.join(packages)}{COLORS['ENDC']}\n")
        sys.exit(1)

    if missing_optional:
        log("[!] Missing optional tools (limited functionality):", "WARNING")
        for dep in missing_optional[:6]:
            print(f"    {dep}")
        if len(missing_optional) > 6:
            print(f"    ... and {len(missing_optional) - 6} more")
        print()

check_dependencies()

# === PROGRESS BAR ===
def progress_bar(current, total, task="Processing"):
    percent  = int((current / total) * 100) if total > 0 else 100
    bar_len  = 40
    filled   = int((current / total) * bar_len) if total > 0 else bar_len
    bar      = '█' * filled + '░' * (bar_len - filled)
    print(f"\r{COLORS['CYAN']}[{bar}] {percent}% - {task}{COLORS['ENDC']}", end='', flush=True)
    if current >= total:
        print()

# === MAGIC SIGNATURES ===
MAGIC_SIGS = {
    b'\x89PNG':        'PNG',
    b'\xff\xd8\xff':   'JPEG',
    b'GIF8':           'GIF',
    b'%PDF':           'PDF',
    b'PK\x03\x04':    'ZIP',
    b'\x7fELF':        'ELF',
    b'MZ':             'PE/MZ',
    b'BZh':            'BZIP2',
    b'\x1f\x8b':       'GZIP',
    b'7z\xbc\xaf':     '7-ZIP',
    b'Rar!':           'RAR',
    b'OggS':           'OGG',
    b'fLaC':           'FLAC',
    b'ID3':            'MP3',
    b'\xff\xfb':       'MP3 (no ID3)',
    b'RIFF':           'RIFF (WAV/AVI/WEBP)',
    b'\xca\xfe\xba\xbe': 'Mach-O FAT',
    b'\xfe\xed\xfa\xce': 'Mach-O 32-bit',
    b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit',
    b'dex\n':          'DEX (Android)',
    b'CAFEBABE':       'Java Class',
}

# === CRYPTO/SUSPICIOUS PATTERNS ===
CRYPTO_CONSTANTS = {
    b'\x67\x45\x23\x01\xef\xcd\xab\x89': 'MD5 init constants',
    b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5': 'AES S-box',
    b'\x42\x8a\x2f\x98\xd7\x28\xae\x22': 'SHA-256 K constants',
    b'\x6a\x09\xe6\x67\xf3\xbc\xc9\x08': 'SHA-512 init constants',
}

SUSPICIOUS_STRINGS = [
    # Shells / execution
    r'/bin/(ba)?sh',
    r'cmd\.exe',
    r'powershell',
    r'WScript',
    r'eval\s*\(',
    r'exec\s*\(',
    r'system\s*\(',
    # Network
    r'https?://\S+',
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    r'[\w\.-]+@[\w\.-]+\.\w+',
    r'://.{1,80}\.onion',
    # Credentials / keys
    r'password\s*[:=]\s*\S+',
    r'passwd\s*[:=]\s*\S+',
    r'api[_-]?key\s*[:=]\s*\S+',
    r'secret\s*[:=]\s*\S+',
    r'-----BEGIN (?:RSA|OPENSSH|PGP) ',
    # Common malware strings
    r'CreateRemoteThread',
    r'VirtualAllocEx',
    r'WriteProcessMemory',
    r'LoadLibrary',
    r'GetProcAddress',
    r'NtUnmapViewOfSection',
    r'IsDebuggerPresent',
    r'CheckRemoteDebuggerPresent',
]

# === MEMORY ANALYZER ===
class MemoryAnalyzer:
    def __init__(self, filepath, output_dir):
        self.filepath   = filepath
        self.output_dir = output_dir
        self.vol_cmd    = None
        self.vol_version = None
        self.profile    = None
        self._detect_volatility()

    def _detect_volatility(self):
        for cmd in ['vol.py', 'volatility3', 'vol3', 'volatility']:
            if shutil.which(cmd):
                self.vol_cmd = cmd
                try:
                    result = subprocess.run([cmd, '--version'],
                                            capture_output=True, text=True, timeout=5)
                    out = result.stdout + result.stderr
                    self.vol_version = 3 if ('Volatility 3' in out or 'vol3' in cmd or 'vol.py' in cmd) else 2
                    break
                except Exception:
                    continue

    def is_memory_dump(self):
        ext = os.path.splitext(self.filepath)[1].lower()
        if ext in ['.vmem', '.mem', '.dmp', '.raw', '.dd', '.lime', '.vmsn', '.bin']:
            return True
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(4096)
            if header.startswith(b'PAGEDUMP') or header.startswith(b'PAGE'):
                return True
            if header.startswith(b'\x7fELF') and b'CORE' in header[:100]:
                return True
            # LIME format
            if header[:4] == b'\x45\x4c\x4d\x45':
                return True
        except Exception:
            pass
        return False

    @functools.lru_cache(maxsize=1)
    def detect_profile(self):
        if not self.vol_cmd:
            return None
        log("    Detecting memory profile...", "CYAN")
        try:
            if self.vol_version == 3:
                result = subprocess.run([self.vol_cmd, '-f', self.filepath, 'banners.Banners'],
                                        capture_output=True, text=True, timeout=30)
                if 'Windows' in result.stdout:
                    return "Windows"
                elif 'Linux' in result.stdout:
                    return "Linux"
            else:
                result = subprocess.run([self.vol_cmd, '-f', self.filepath, 'imageinfo'],
                                        capture_output=True, text=True, timeout=60)
                profiles = re.findall(r'Suggested Profile\(s\) : (.+)', result.stdout)
                if profiles:
                    return profiles[0].split(',')[0].strip()
        except Exception:
            pass
        return None

    def run_vol_plugin(self, plugin, extra_args=None):
        if not self.vol_cmd:
            return ""
        try:
            if self.vol_version == 3:
                cmd = [self.vol_cmd, '-f', self.filepath, plugin]
            else:
                cmd = [self.vol_cmd, '-f', self.filepath, plugin]
                if self.profile:
                    cmd.insert(3, f'--profile={self.profile}')
            if extra_args:
                cmd.extend(extra_args)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "[Timeout after 120s]"
        except Exception as e:
            return f"[Error: {e}]"

    def full_memory_analysis(self):
        if not self.vol_cmd:
            return "[!] Volatility not installed\n    Install: pip3 install volatility3"

        log(f"\n[*] Using Volatility {self.vol_version}", "GREEN")
        self.profile = self.detect_profile()
        if self.profile:
            log(f"[*] Profile: {self.profile}", "GREEN")

        report = [f"\n{'='*60}", "MEMORY DUMP ANALYSIS", f"{'='*60}",
                  f"File: {self.filepath}", f"Profile: {self.profile or 'Auto-detect'}\n"]

        plugins_v3 = {
            'Process List':      'windows.pslist.PsList',
            'Process Tree':      'windows.pstree.PsTree',
            'Network Conns':     'windows.netscan.NetScan',
            'Command Lines':     'windows.cmdline.CmdLine',
            'DLL List':          'windows.dlllist.DllList',
            'Handles':           'windows.handles.Handles',
            'Registry Hives':    'windows.registry.hivelist.HiveList',
        }
        plugins_v2 = {
            'Process List':  'pslist',
            'Process Tree':  'pstree',
            'Network Conns': 'netscan',
            'Command Lines': 'cmdline',
            'DLL List':      'dlllist',
        }
        plugins = plugins_v3 if self.vol_version == 3 else plugins_v2

        completed = 0
        total = len(plugins)

        for name, plugin in plugins.items():
            progress_bar(completed, total, f"Running {name}")
            output = self.run_vol_plugin(plugin)
            report.append(f"\n[+] {name.upper()}:")
            lines = output.splitlines()
            report.extend(lines[:25] if len(lines) > 25 else lines)
            if len(lines) > 25:
                report.append(f"    ... ({len(lines) - 25} more lines)")
            completed += 1
            progress_bar(completed, total, f"Running {name}")

        progress_bar(total, total, "Memory analysis complete")
        return "\n".join(report)


# === FORENSICS AGENT ===
class ForensicsAgent:
    def __init__(self, filepath):
        self.filepath   = filepath
        self.filename   = os.path.basename(filepath)
        self.filesize   = os.path.getsize(filepath)
        timestamp       = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"forensics_{self.filename}_{timestamp}"
        self._strings_cache = {}
        self._hash_cache    = None

    def compute_hashes(self):
        if self._hash_cache:
            return self._hash_cache
        hashes = {}
        try:
            with open(self.filepath, 'rb') as f:
                if self.filesize > 100 * 1024 * 1024:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        hashes['MD5']    = hashlib.md5(mm).hexdigest()
                        hashes['SHA1']   = hashlib.sha1(mm).hexdigest()
                        hashes['SHA256'] = hashlib.sha256(mm).hexdigest()
                        mm.seek(0)
                        hashes['SHA512'] = hashlib.sha512(mm).hexdigest()
                else:
                    data = f.read()
                    hashes['MD5']    = hashlib.md5(data).hexdigest()
                    hashes['SHA1']   = hashlib.sha1(data).hexdigest()
                    hashes['SHA256'] = hashlib.sha256(data).hexdigest()
                    hashes['SHA512'] = hashlib.sha512(data).hexdigest()
        except PermissionError:
            hashes['error'] = 'Permission denied'
        except MemoryError:
            hashes['error'] = 'File too large for memory'
        except OSError as e:
            hashes['error'] = str(e)

        # Fuzzy hashes (ssdeep / TLSH)
        try:
            if shutil.which('ssdeep'):
                result = subprocess.run(
                    ['ssdeep', '-b', self.filepath],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().splitlines():
                    if line and not line.startswith('ssdeep,'):
                        hashes['SSDEEP'] = line.split(',')[0] if ',' in line else line
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        try:
            if shutil.which('tlsh'):
                result = subprocess.run(
                    ['tlsh', '-f', self.filepath],
                    capture_output=True, text=True, timeout=15
                )
                if result.stdout.strip():
                    hashes['TLSH'] = result.stdout.strip().split()[0]
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        self._hash_cache = hashes
        return hashes

    def get_file_size_human(self):
        size = self.filesize
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def get_file_type(self):
        try:
            result = subprocess.run(['file', '-b', self.filepath],
                                    capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return "Unknown"

    def extract_strings(self, min_len=6):
        if min_len in self._strings_cache:
            return self._strings_cache[min_len]
        try:
            result = subprocess.run(
                ['strings', '-a', '-n', str(min_len), self.filepath],
                capture_output=True, text=True, timeout=30
            )
            strings = result.stdout.splitlines()
        except Exception:
            strings = []
        self._strings_cache[min_len] = strings
        return strings

    def find_flags(self):
        strings = self.extract_strings(4)
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'thm\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'PICO\{[^}]+\}',
            r'ductf\{[^}]+\}',
            r'dice\{[^}]+\}',
        ]
        flags = set()
        for s in strings:
            for pattern in patterns:
                if m := re.search(pattern, s, re.IGNORECASE):
                    flags.add(m.group())
        return list(flags)

    def analyze_entropy(self):
        try:
            read_size = min(1024 * 1024, self.filesize)
            with open(self.filepath, 'rb') as f:
                data = f.read(read_size)
            if not data:
                return 0.0, "Empty file", []

            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1

            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p)

            # Block entropy (detect encrypted sections)
            block_size = 256
            block_entropies = []
            for i in range(0, min(len(data), 8192), block_size):
                block = data[i:i + block_size]
                if len(block) < 16:
                    continue
                bfreq = {}
                for b in block:
                    bfreq[b] = bfreq.get(b, 0) + 1
                be = 0.0
                for cnt in bfreq.values():
                    p = cnt / len(block)
                    be -= p * math.log2(p)
                block_entropies.append(be)

            if entropy > 7.5:
                assessment = "Very high — likely encrypted/compressed"
            elif entropy > 6.5:
                assessment = "High — possibly compressed or obfuscated"
            elif entropy > 4.0:
                assessment = "Medium — mixed data"
            else:
                assessment = "Low — structured/repetitive data"

            return entropy, assessment, block_entropies
        except Exception as e:
            return 0.0, f"Error: {e}", []

    def detect_crypto_constants(self):
        findings = []
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read(min(512 * 1024, self.filesize))
            for pattern, name in CRYPTO_CONSTANTS.items():
                if pattern in data:
                    findings.append(name)
        except Exception:
            pass
        return findings

    def get_exif_data(self):
        if not shutil.which('exiftool'):
            return {}
        try:
            result = subprocess.run(
                ['exiftool', '-j', '-a', '-u', self.filepath],
                capture_output=True, text=True, timeout=15
            )
            data = json.loads(result.stdout)
            return data[0] if data else {}
        except Exception:
            return {}

    def find_interesting_strings(self):
        strings = self.extract_strings(4)
        findings = {
            'urls':        [],
            'emails':      [],
            'ips':         [],
            'paths':       [],
            'suspicious':  [],
            'base64_blobs':[],
            'keys':        [],
        }

        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

        for s in strings[:10000]:
            # URLs
            if re.match(r'https?://', s):
                findings['urls'].append(s[:200])
            # Emails
            if m := re.search(r'[\w\.-]+@[\w\.-]+\.\w+', s):
                findings['emails'].append(m.group())
            # IPs (exclude obviously wrong ones)
            if m := re.search(r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b', s):
                ip = m.group()
                if not ip.startswith('0.0.0.'):
                    findings['ips'].append(ip)
            # File paths
            if re.match(r'^(/[a-zA-Z]|C:\\)', s) and len(s) < 200:
                findings['paths'].append(s)
            # Suspicious strings
            for pattern in SUSPICIOUS_STRINGS:
                if re.search(pattern, s, re.IGNORECASE):
                    findings['suspicious'].append(s[:150])
                    break
            # Base64 blobs (long ones only — short matches are noise)
            if len(s) >= 64 and b64_pattern.fullmatch(s):
                findings['base64_blobs'].append(s[:80] + '...' if len(s) > 80 else s)
            # Key-value credential patterns
            if re.search(r'(?:password|passwd|secret|api.?key|token)\s*[:=]\s*\S+', s, re.I):
                findings['keys'].append(s[:150])

        # Deduplicate and cap
        for key in findings:
            seen = set()
            deduped = []
            for item in findings[key]:
                if item not in seen:
                    seen.add(item)
                    deduped.append(item)
            findings[key] = deduped[:15]

        return findings

    def run_binwalk(self):
        if not shutil.which('binwalk'):
            return "", []
        try:
            result = subprocess.run(
                ['binwalk', self.filepath],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout, []
        except Exception as e:
            return f"Error running binwalk: {e}", []

    def run_foremost(self):
        if not shutil.which('foremost'):
            return "", []
        try:
            output_dir = os.path.join(self.output_dir, 'foremost')
            os.makedirs(output_dir, exist_ok=True)
            subprocess.run(
                ['foremost', '-o', output_dir, self.filepath],
                capture_output=True, timeout=60
            )
            carved = [
                os.path.join(root, fname)
                for root, _, files in os.walk(output_dir)
                for fname in files
            ]
            return f"Carved to {output_dir}", carved
        except Exception as e:
            return f"Error running foremost: {e}", []

    def check_steganography(self):
        findings = []
        try:
            file_type = self.get_file_type().lower()
            with open(self.filepath, 'rb') as f:
                data = f.read()

            if 'jpeg' in file_type or 'jpg' in file_type:
                if not data.endswith(b'\xff\xd9'):
                    findings.append("JPEG missing EOI marker — possible trailing data")
                # Check for multiple JPEG SOI markers
                soi_count = data.count(b'\xff\xd8')
                if soi_count > 1:
                    findings.append(f"Multiple JPEG SOI markers found ({soi_count}) — possible embedded JPEG")

            if 'png' in file_type:
                if not data.endswith(b'IEND\xae\x42\x60\x82'):
                    findings.append("PNG missing IEND chunk — possible trailing data")
                # Check for tEXt/zTXt/iTXt chunks
                for chunk_type in [b'tEXt', b'zTXt', b'iTXt']:
                    if chunk_type in data:
                        findings.append(f"PNG has {chunk_type.decode()} chunk — may contain hidden text")

            if 'zip' in file_type or data.startswith(b'PK'):
                # Check for appended data after ZIP EOCD
                eocd = data.rfind(b'PK\x05\x06')
                if eocd != -1:
                    eocd_end = eocd + 22
                    comment_len = struct.unpack('<H', data[eocd + 20:eocd + 22])[0]
                    total_end = eocd_end + comment_len
                    if total_end < len(data):
                        extra = len(data) - total_end
                        findings.append(f"ZIP has {extra} bytes of appended data after EOCD")

        except Exception:
            pass
        return findings

    def analyze_hex_header(self):
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(32)
            hex_dump   = ' '.join(f'{b:02x}' for b in header)
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header)
            magic = "Unknown"
            for sig, name in MAGIC_SIGS.items():
                if header.startswith(sig):
                    magic = name
                    break
            return hex_dump, ascii_repr, magic
        except Exception:
            return "", "", "Error"

    def analyze_elf_sections(self):
        """Parse ELF sections looking for suspicious names or rwx permissions."""
        if not shutil.which('readelf'):
            return []
        findings = []
        try:
            result = subprocess.run(
                ['readelf', '-S', '--wide', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if 'WX' in line or 'rwx' in line.lower():
                    findings.append(f"RWX section: {line.strip()}")
                for suspicious in ['.upx', 'UPX', '.pack', '.enc', '.crypted']:
                    if suspicious in line:
                        findings.append(f"Suspicious section: {line.strip()}")
        except Exception:
            pass
        return findings

    def analyze_pe_section_entropy(self):
        """Calculate entropy per PE section to detect packed/encrypted sections."""
        findings = []
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read(min(5 * 1024 * 1024, self.filesize))
            if not data.startswith(b'MZ'):
                return findings
            # Locate PE header
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return findings
            num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
            opt_hdr_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
            section_offset = pe_offset + 24 + opt_hdr_size
            for i in range(min(num_sections, 50)):
                sec = data[section_offset + i*40 : section_offset + (i+1)*40]
                if len(sec) < 40:
                    break
                name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
                raw_size = struct.unpack('<I', sec[16:20])[0]
                raw_offset = struct.unpack('<I', sec[20:24])[0]
                characteristics = struct.unpack('<I', sec[36:40])[0]
                if raw_size > 0 and raw_offset + raw_size <= len(data):
                    section_data = data[raw_offset:raw_offset+raw_size]
                    freq = {}
                    for b in section_data:
                        freq[b] = freq.get(b, 0) + 1
                    ent = -sum((c/len(section_data)) * math.log2(c/len(section_data))
                               for c in freq.values())
                    status = ''
                    if ent > 7.5:
                        status = ' ← LIKELY PACKED/ENCRYPTED'
                    elif ent > 6.8:
                        status = ' ← compressed?'
                    rwx = ''
                    if characteristics & 0x20000000 and characteristics & 0x40000000 and characteristics & 0x80000000:
                        rwx = ' [RWX!]'
                    findings.append(f"{name}: entropy={ent:.2f}, size={raw_size}{rwx}{status}")
        except Exception:
            pass
        return findings

    def run_yara_scan(self):
        """Run YARA rules if available."""
        if not shutil.which('yara'):
            return []
        findings = []
        yara_dirs = [
            os.path.expanduser('~/.yara/rules'),
            '/usr/share/yara',
            '/opt/yara-rules',
        ]
        for ydir in yara_dirs:
            if os.path.isdir(ydir):
                for rule_file in os.listdir(ydir):
                    if rule_file.endswith(('.yar', '.yara')):
                        rule_path = os.path.join(ydir, rule_file)
                        try:
                            result = subprocess.run(
                                ['yara', '-s', rule_path, self.filepath],
                                capture_output=True, text=True, timeout=30
                            )
                            for line in result.stdout.splitlines():
                                if line.strip():
                                    findings.append(line.strip())
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            continue
                    if len(findings) >= 20:
                        break
            if len(findings) >= 20:
                break
        return findings[:20]

    def analyze_pe_imports(self):
        """Heuristic: extract imported function names from strings for PE files."""
        strings = self.extract_strings(4)
        dangerous_imports = {
            'CreateRemoteThread':   'Process injection',
            'VirtualAllocEx':       'Remote memory allocation',
            'WriteProcessMemory':   'Process injection',
            'SetWindowsHookEx':     'Keylogger / hook',
            'GetAsyncKeyState':     'Keylogger',
            'URLDownloadToFile':    'Downloader',
            'WinExec':              'Code execution',
            'ShellExecute':         'Code execution',
            'IsDebuggerPresent':    'Anti-debug',
            'CheckRemoteDebuggerPresent': 'Anti-debug',
            'NtUnmapViewOfSection': 'Process hollowing',
            'ZwUnmapViewOfSection': 'Process hollowing',
            'OpenProcess':          'Process access',
            'RegSetValueEx':        'Registry persistence',
            'InternetOpen':         'Network access',
            'HttpSendRequest':      'HTTP exfil',
            'CryptEncrypt':         'Encryption',
            'CryptDecrypt':         'Decryption',
        }
        found = {}
        for s in strings:
            if s in dangerous_imports:
                found[s] = dangerous_imports[s]
        return found

    def full_analysis(self):
        os.makedirs(self.output_dir, exist_ok=True)
        report = []

        log("\n" + "=" * 60, "HEADER")
        log("FORENSICS ANALYSIS REPORT", "HEADER")
        log("=" * 60, "HEADER")

        # File type
        file_type = self.get_file_type()
        report.append(f"File:  {self.filepath}")
        report.append(f"Size:  {self.get_file_size_human()} ({self.filesize} bytes)")
        report.append(f"Type:  {file_type}")

        # Hashes
        hashes = self.compute_hashes()
        report.append(f"\n[*] HASHES:")
        for algo, h in hashes.items():
            report.append(f"    {algo}: {h}")
        report.append(f"\n    VirusTotal: https://www.virustotal.com/gui/file/{hashes.get('SHA256', '')}")

        # Header
        hex_dump, ascii_repr, magic = self.analyze_hex_header()
        report.append(f"\n[*] HEADER:")
        report.append(f"    Magic:  {magic}")
        report.append(f"    Hex:    {hex_dump[:48]}...")
        report.append(f"    ASCII:  {ascii_repr[:24]}...")

        # Entropy
        entropy, assessment, block_ent = self.analyze_entropy()
        report.append(f"\n[*] ENTROPY: {entropy:.3f}/8.0 — {assessment}")
        if block_ent:
            high_blocks = sum(1 for be in block_ent if be > 7.0)
            if high_blocks > 0:
                report.append(f"    High-entropy blocks: {high_blocks}/{len(block_ent)} (possible packed sections)")

        # Crypto constants
        crypto = self.detect_crypto_constants()
        if crypto:
            report.append(f"\n[!] CRYPTO CONSTANTS DETECTED:")
            for c in crypto:
                report.append(f"    - {c}")

        # Parallel slow operations
        print()
        results   = {}
        tasks_map = {
            'flags':    self.find_flags,
            'strings':  self.find_interesting_strings,
            'exif':     self.get_exif_data,
            'stego':    self.check_steganography,
            'binwalk':  self.run_binwalk,
        }
        # Add ELF/PE analysis if applicable
        if 'ELF' in file_type:
            tasks_map['elf_sections']  = self.analyze_elf_sections
        if 'PE' in magic or 'MZ' in magic:
            tasks_map['pe_imports']    = self.analyze_pe_imports
            tasks_map['pe_entropy']    = self.analyze_pe_section_entropy
        # YARA scan
        if shutil.which('yara'):
            tasks_map['yara'] = self.run_yara_scan

        total_tasks = len(tasks_map)
        completed   = 0
        progress_bar(0, total_tasks, "Analyzing")

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(fn): name for name, fn in tasks_map.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = None
                    log(f"\n[!] Task '{name}' failed: {e}", "WARNING")
                completed += 1
                progress_bar(completed, total_tasks, "Analyzing")

        # Flags
        if flags := results.get('flags'):
            report.append(f"\n[!!!] FLAGS FOUND ({len(flags)}):")
            for f in flags:
                report.append(f"    {COLORS['GREEN']}{f}{COLORS['ENDC']}")

        # Interesting strings
        if interesting := results.get('strings'):
            for category, items in interesting.items():
                if items:
                    report.append(f"\n[+] {category.upper()} ({len(items)}):")
                    for item in items[:8]:
                        report.append(f"    - {item}")

        # EXIF
        if exif := results.get('exif'):
            if isinstance(exif, dict) and exif:
                report.append(f"\n[+] METADATA ({len(exif)} fields):")
                skip = {'SourceFile', 'ExifToolVersion', 'FileAccessDate', 'FileInodeChangeDate'}
                for k, v in list(exif.items())[:20]:
                    if k not in skip:
                        report.append(f"    {k}: {str(v)[:80]}")

        # Stego
        if stego := results.get('stego'):
            report.append(f"\n[!] STEGANOGRAPHY INDICATORS:")
            for s in stego:
                report.append(f"    - {s}")

        # Binwalk
        if binwalk_out := results.get('binwalk'):
            output, _ = binwalk_out if isinstance(binwalk_out, tuple) else (binwalk_out, [])
            if output and 'DECIMAL' in output:
                report.append(f"\n[+] BINWALK SIGNATURES:")
                for line in output.splitlines()[3:15]:
                    if line.strip():
                        report.append(f"    {line}")

        # ELF sections
        if elf_secs := results.get('elf_sections'):
            report.append(f"\n[!] ELF SECTION ANOMALIES:")
            for s in elf_secs:
                report.append(f"    - {s}")

        # PE imports
        if pe_imports := results.get('pe_imports'):
            report.append(f"\n[!] DANGEROUS IMPORTS ({len(pe_imports)}):")
            for func, reason in pe_imports.items():
                report.append(f"    - {func}: {reason}")

        # PE section entropy
        if pe_ent := results.get('pe_entropy'):
            report.append(f"\n[+] PE SECTION ENTROPY:")
            for s in pe_ent:
                report.append(f"    - {s}")

        # YARA matches
        if yara_hits := results.get('yara'):
            report.append(f"\n[!!!] YARA MATCHES ({len(yara_hits)}):")
            for hit in yara_hits:
                report.append(f"    - {hit}")

        report.append(f"\n[*] Output directory: {self.output_dir}")
        report.append(f"{'=' * 60}")

        # Save report
        report_file = os.path.join(self.output_dir, "report.txt")
        with open(report_file, "w") as f:
            # Strip ANSI codes for file
            clean = re.sub(r'\033\[[0-9;]+m', '', "\n".join(report))
            f.write(clean)

        return "\n".join(report)


# === MAIN ===
def show_help():
    log(f"\n--- Forensics Analyzer ---\n", "HEADER")
    print("Usage: ./Forensics-Analyzer.py <file> [options]")
    print("\nOptions:")
    print("  --auto            Automatic mode (no prompts)")
    print("  --json            Output report as JSON")
    print("  -h, --help        Show this help")
    print("  -v, --version     Show version")
    print("\nExamples:")
    print("  ./Forensics-Analyzer.py suspicious.exe")
    print("  ./Forensics-Analyzer.py memory.dmp --auto")
    print("  ./Forensics-Analyzer.py malware.bin --json")
    sys.exit(0)


def main():
    log(f"\n--- Forensics Analyzer ---\n", "HEADER")

    if '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    if '-v' in sys.argv or '--version' in sys.argv:
        print(f"Forensics-Analyzer")
        sys.exit(0)

    args      = [a for a in sys.argv[1:] if not a.startswith("-")]
    auto_mode = "--auto" in sys.argv
    json_mode = "--json" in sys.argv

    if not args:
        log("Usage: ./Forensics-Analyzer.py <file> [--auto] [--json]", "FAIL")
        log("Run './Forensics-Analyzer.py --help' for full usage.", "CYAN")
        sys.exit(1)

    target = args[0]
    if not os.path.exists(target):
        log(f"[-] File '{target}' not found.", "FAIL")
        sys.exit(1)

    if not os.access(target, os.R_OK):
        log(f"[-] Permission denied: '{target}'", "FAIL")
        sys.exit(1)

    file_size = os.path.getsize(target)
    if file_size == 0:
        log(f"[-] File is empty: '{target}'", "FAIL")
        sys.exit(1)

    if file_size > MAX_FILE_SIZE:
        log(f"[-] File too large ({file_size / (1024**3):.1f} GB). Max: {MAX_FILE_SIZE / (1024**3):.0f} GB", "FAIL")
        sys.exit(1)

    log(f"[*] Analyzing: {target}\n", "BOLD")

    agent        = ForensicsAgent(target)
    mem_analyzer = MemoryAnalyzer(target, agent.output_dir)

    if mem_analyzer.is_memory_dump():
        log("[!] Memory dump detected!", "WARNING")
        os.makedirs(agent.output_dir, exist_ok=True)
        result = mem_analyzer.full_memory_analysis()
        print(result)
    else:
        result = agent.full_analysis()
        print(result)

    # JSON output
    if json_mode:
        json_report = {
            'file': target,
            'size': file_size,
            'hashes': agent.compute_hashes(),
            'type': agent.get_file_type(),
        }
        json_file = os.path.join(agent.output_dir, 'report.json')
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        log(f"\n[*] JSON report: {json_file}", "CYAN")

    log("\n[*] Analysis Complete.", "BOLD")


if __name__ == "__main__":
    main()
