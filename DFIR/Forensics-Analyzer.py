#!/usr/bin/env python3

print('''

8""""8                                                                                                    
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
import mmap
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import functools

# === COLORS ===
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'YELLOW': '\033[33m',
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['ENDC']}")

# === DEPENDENCY CHECK ===
REQUIRED_DEPS = {
    'file': 'file',
    'strings': 'binutils',
}

OPTIONAL_DEPS = {
    'binwalk': 'binwalk',
    'foremost': 'foremost',
    'exiftool': 'libimage-exiftool-perl',
    'volatility': 'volatility',
    'vol.py': 'volatility3',
}

def check_dependencies():
    """Comprehensive dependency checking with installation hints"""
    missing_required = []
    missing_optional = []
    
    log("[*] Checking dependencies...", "BLUE")
    
    # Check required
    for tool, package in REQUIRED_DEPS.items():
        if not shutil.which(tool):
            missing_required.append(f"{tool} ({package})")
    
    # Check optional
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
        
        packages = [REQUIRED_DEPS[tool.split()[0]] for tool in missing_required]
        print(f"\n{COLORS['WARNING']}Install with:{COLORS['ENDC']}")
        print(f"    {COLORS['BOLD']}sudo apt install {' '.join(set(packages))}{COLORS['ENDC']}\n")
        sys.exit(1)
    
    if missing_optional:
        log("[!] Missing optional tools (limited functionality):", "WARNING")
        for dep in missing_optional[:5]:  # Show first 5
            print(f"    {dep}")
        if len(missing_optional) > 5:
            print(f"    ... and {len(missing_optional) - 5} more")
        print()

check_dependencies()

# === PROGRESS BAR ===
def progress_bar(current, total, task="Processing"):
    """Simple progress bar"""
    percent = int((current / total) * 100) if total > 0 else 100
    bar_len = 40
    filled = int((current / total) * bar_len) if total > 0 else bar_len
    bar = '█' * filled + '░' * (bar_len - filled)
    print(f"\r{COLORS['CYAN']}[{bar}] {percent}% - {task}{COLORS['ENDC']}", end='', flush=True)
    if current >= total:
        print()  # New line when complete

# === MEMORY ANALYZER ===
class MemoryAnalyzer:
    """Volatility integration for memory dump analysis"""
    
    def __init__(self, filepath, output_dir):
        self.filepath = filepath
        self.output_dir = output_dir
        self.vol_cmd = None
        self.vol_version = None
        self.profile = None
        
        self._detect_volatility()
    
    def _detect_volatility(self):
        """Detect Volatility version and command"""
        for cmd in ['vol.py', 'volatility3', 'vol3', 'volatility']:
            if shutil.which(cmd):
                self.vol_cmd = cmd
                try:
                    result = subprocess.run([cmd, '--version'], capture_output=True, text=True, timeout=5)
                    output = result.stdout + result.stderr
                    if 'Volatility 3' in output or 'vol3' in cmd or 'vol.py' in cmd:
                        self.vol_version = 3
                    else:
                        self.vol_version = 2
                    break
                except:
                    continue
    
    def is_memory_dump(self):
        """Enhanced memory dump detection"""
        # Check extension first
        ext = os.path.splitext(self.filepath)[1].lower()
        if ext in ['.vmem', '.mem', '.dmp', '.raw', '.dd', '.lime', '.vmsn', '.bin']:
            return True
        
        # Check magic bytes
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(4096)
            
            # Windows crash dump
            if header.startswith(b'PAGEDUMP') or header.startswith(b'PAGE'):
                return True
            
            # ELF core dump
            if header.startswith(b'\x7fELF'):
                if b'CORE' in header[:100]:
                    return True
            
            # Size heuristic (> 50MB likely memory dump)
            if os.path.getsize(self.filepath) > 50 * 1024 * 1024:
                # Check for common memory patterns
                if b'\x00\x00\x00\x00' * 100 in header:
                    return True
        except:
            pass
        
        return False
    
    @functools.lru_cache(maxsize=1)
    def detect_profile(self):
        """Auto-detect memory profile with caching"""
        if not self.vol_cmd:
            return None
        
        log("    Detecting memory profile...", "CYAN")
        
        try:
            if self.vol_version == 3:
                # Vol3 uses banners
                result = subprocess.run([self.vol_cmd, '-f', self.filepath, 'banners.Banners'],
                                      capture_output=True, text=True, timeout=30)
                output = result.stdout
                
                if 'Windows' in output:
                    return "Windows"
                elif 'Linux' in output:
                    return "Linux"
            else:
                # Vol2 uses imageinfo
                result = subprocess.run([self.vol_cmd, '-f', self.filepath, 'imageinfo'],
                                      capture_output=True, text=True, timeout=60)
                profiles = re.findall(r'Suggested Profile\(s\) : (.+)', result.stdout)
                if profiles:
                    return profiles[0].split(',')[0].strip()
        except:
            pass
        
        return None
    
    def run_vol_plugin(self, plugin, args=''):
        """Run volatility plugin with error handling"""
        if not self.vol_cmd:
            return ""
        
        try:
            if self.vol_version == 3:
                cmd = [self.vol_cmd, '-f', self.filepath, plugin]
            else:
                if self.profile:
                    cmd = [self.vol_cmd, '-f', self.filepath, f'--profile={self.profile}', plugin]
                else:
                    cmd = [self.vol_cmd, '-f', self.filepath, plugin]
            
            if args:
                cmd.extend(args.split())
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"[Timeout after 120s]"
        except Exception as e:
            return f"[Error: {e}]"
    
    def full_memory_analysis(self):
        """Complete memory forensics analysis"""
        if not self.vol_cmd:
            return "[!] Volatility not installed\n    Install: pip3 install volatility3"
        
        log(f"\n[*] Using Volatility {self.vol_version}", "GREEN")
        
        # Detect profile
        self.profile = self.detect_profile()
        if self.profile:
            log(f"[*] Profile: {self.profile}", "GREEN")
        
        report = []
        report.append(f"\n{'='*60}")
        report.append("MEMORY DUMP ANALYSIS")
        report.append(f"{'='*60}")
        report.append(f"File: {self.filepath}")
        report.append(f"Profile: {self.profile or 'Auto-detect'}\n")
        
        # Define plugins to run
        plugins = {
            'Process List': 'windows.pslist.PsList' if self.vol_version == 3 else 'pslist',
            'Network Connections': 'windows.netscan.NetScan' if self.vol_version == 3 else 'netscan',
            'Command History': 'windows.cmdline.CmdLine' if self.vol_version == 3 else 'cmdline',
        }
        
        completed = 0
        total = len(plugins)
        
        for name, plugin in plugins.items():
            progress_bar(completed, total, f"Running {name}")
            output = self.run_vol_plugin(plugin)
            
            report.append(f"\n[+] {name.upper()}:")
            lines = output.splitlines()
            report.extend(lines[:20] if len(lines) > 20 else lines)
            if len(lines) > 20:
                report.append(f"    ... ({len(lines) - 20} more lines)")
            
            completed += 1
            progress_bar(completed, total, f"Running {name}")
        
        progress_bar(total, total, "Memory analysis complete")
        
        return "\n".join(report)

# === FORENSICS AGENT ===
class ForensicsAgent:
    """Main forensics analysis class with optimizations"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%H%M%S')
        self.output_dir = f"forensics_{self.filename}_{timestamp}"
        self.strings_cache = {}  # Cache for string extraction
    
    def __del__(self):
        """Cleanup cache"""
        self.strings_cache.clear()
    
    @functools.lru_cache(maxsize=32)
    def compute_hashes(self):
        """Compute file hashes using mmap for large files"""
        hashes = {}
        
        try:
            # Use mmap for efficient reading
            with open(self.filepath, 'rb') as f:
                if os.path.getsize(self.filepath) > 100 * 1024 * 1024:  # > 100MB
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                        hashes['MD5'] = hashlib.md5(mmapped).hexdigest()
                        hashes['SHA1'] = hashlib.sha1(mmapped).hexdigest()
                        hashes['SHA256'] = hashlib.sha256(mmapped).hexdigest()
                else:
                    data = f.read()
                    hashes['MD5'] = hashlib.md5(data).hexdigest()
                    hashes['SHA1'] = hashlib.sha1(data).hexdigest()
                    hashes['SHA256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
        
        return hashes
    
    def get_file_size(self):
        """Get human-readable file size"""
        size = os.path.getsize(self.filepath)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def get_file_type(self):
        """Get file type using file command"""
        try:
            result = subprocess.run(['file', '-b', self.filepath], 
                                  capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def extract_strings(self, min_len=6):
        """Extract strings with caching"""
        if min_len in self.strings_cache:
            return self.strings_cache[min_len]
        
        try:
            result = subprocess.run(['strings', '-a', '-n', str(min_len), self.filepath],
                                  capture_output=True, text=True, timeout=30)
            strings = result.stdout.splitlines()
            self.strings_cache[min_len] = strings
            return strings
        except:
            return []
    
    def find_flags(self):
        """Find CTF flags"""
        strings = self.extract_strings(4)
        flags = []
        
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'thm\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
        ]
        
        for s in strings:
            for pattern in patterns:
                if match := re.search(pattern, s, re.IGNORECASE):
                    flags.append(match.group())
        
        return list(set(flags))
    
    def analyze_entropy(self):
        """Calculate file entropy"""
        import math
        
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read(min(1024 * 1024, os.path.getsize(self.filepath)))  # First 1MB
            
            if not data:
                return 0.0, "Empty file"
            
            freq = {}
            for byte in data:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p)
            
            # Assessment
            if entropy > 7.5:
                assessment = "Very high - likely encrypted/compressed"
            elif entropy > 6.0:
                assessment = "High - possibly compressed"
            elif entropy > 4.0:
                assessment = "Medium - mixed data"
            else:
                assessment = "Low - repetitive data"
            
            return entropy, assessment
        except Exception as e:
            return 0.0, f"Error: {e}"
    
    def get_exif_data(self):
        """Extract EXIF metadata"""
        if not shutil.which('exiftool'):
            return {"info": "exif tool not installed"}
        
        try:
            result = subprocess.run(['exiftool', '-j', self.filepath],
                                  capture_output=True, text=True, timeout=15)
            import json
            data = json.loads(result.stdout)
            return data[0] if data else {}
        except:
            return {}
    
    def find_interesting_strings(self):
        """Find URLs, IPs, emails, etc."""
        strings = self.extract_strings(4)
        findings = {
            'urls': [],
            'emails': [],
            'ips': [],
            'paths': [],
        }
        
        for s in strings[:5000]:  # Limit for performance
            # URLs
            if re.match(r'https?://', s):
                findings['urls'].append(s)
            
            # Emails
            if email := re.search(r'[\w\.-]+@[\w\.-]+\.\w+', s):
                findings['emails'].append(email.group())
            
            # IPs
            if ip := re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
                findings['ips'].append(ip.group())
            
            # File paths
            if re.match(r'^(/|C:\\)', s):
                findings['paths'].append(s)
        
        # Deduplicate
        for key in findings:
            findings[key] = list(set(findings[key]))[:10]  # Top 10
        
        return findings
    
    def run_binwalk(self):
        """Run binwalk for signature scanning"""
        if not shutil.which('binwalk'):
            return "", []
        
        try:
            result = subprocess.run(['binwalk', self.filepath],
                                  capture_output=True, text=True, timeout=30)
            return result.stdout, []
        except:
            return"Error running binwalk", []
    
    def run_foremost(self):
        """Run foremost for file carving"""
        if not shutil.which('foremost'):
            return "", []
        
        try:
            output_dir = os.path.join(self.output_dir, 'foremost')
            os.makedirs(output_dir, exist_ok=True)
            
            subprocess.run(['foremost', '-o', output_dir, self.filepath],
                         capture_output=True, timeout=60)
            
            # Find carved files
            carved = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    carved.append(os.path.join(root, f))
            
            return f"Carved to {output_dir}", carved
        except:
            return "Error running foremost", []
    
    def check_steganography(self):
        """Quick stego check"""
        findings = []
        
        # Check for trailing data
        try:
            file_type = self.get_file_type().lower()
            
            if 'jpeg' in file_type or 'png' in file_type:
                with open(self.filepath, 'rb') as f:
                    data = f.read()
                
                # JPEG ends with FF D9
                if 'jpeg' in file_type and not data.endswith(b'\xff\xd9'):
                    findings.append("JPEG missing EOI marker - possible trailing data")
                
                # PNG ends with IEND
                if 'png' in file_type and not data.endswith(b'IEND\xae\x42\x60\x82'):
                    findings.append("PNG missing IEND chunk - possible trailing data")
        except:
            pass
        
        return findings
    
    def analyze_hex_header(self):
        """Analyze first 16 bytes"""
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(16)
            
            hex_dump = header.hex()
            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header)
            
            # Identify magic
            magic_sigs = {
                b'\x89PNG': 'PNG',
                b'\xff\xd8\xff': 'JPEG',
                b'GIF8': 'GIF',
                b'%PDF': 'PDF',
                b'PK\x03\x04': 'ZIP',
                b'\x7fELF': 'ELF',
                b'MZ': 'PE',
            }
            
            magic = "Unknown"
            for sig, name in magic_sigs.items():
                if header.startswith(sig):
                    magic = name
                    break
            
            return hex_dump, ascii_repr, magic
        except:
            return "", "", "Error"
    
    def full_analysis(self):
        """Run complete forensic analysis with multi-threading"""
        os.makedirs(self.output_dir, exist_ok=True)
        report = []
        
        log("\n" + "="*60, "HEADER")
        log("FORENSICS ANALYSIS REPORT", "HEADER")
        log("="*60, "HEADER")
        
        # Basic info (fast)
        report.append(f"File: {self.filepath}")
        report.append(f"Size: {self.get_file_size()}")
        report.append(f"Type: {self.get_file_type()}")
        
        # Hashes
        hashes = self.compute_hashes()
        report.append(f"\n[*] HASHES:")
        for algo, h in hashes.items():
            report.append(f"    {algo}: {h}")
        
        # Header
        hex_dump, ascii_repr, magic = self.analyze_hex_header()
        report.append(f"\n[*] HEADER ANALYSIS:")
        report.append(f"    Magic: {magic}")
        report.append(f"    Hex: {hex_dump[:48]}...")
        
        # Entropy
        entropy, assessment = self.analyze_entropy()
        report.append(f"\n[*] ENTROPY: {entropy:.2f}/8.0 - {assessment}")
        
        # Parallel slow operations
        print()
        results = {}
        total_tasks = 4
        completed = 0
        
        progress_bar(0, total_tasks, "Analyzing")
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.find_flags): "flags",
                executor.submit(self.find_interesting_strings): "strings",
                executor.submit(self.get_exif_data): "exif",
                executor.submit(self.check_steganography): "stego",
            }
            
            for future in as_completed(futures):
                results[futures[future]] = future.result()
                completed += 1
                progress_bar(completed, total_tasks, "Analyzing")
        
        # Flags
        if flags := results.get('flags'):
            report.append(f"\n[!!!] FLAGS FOUND:")
            for f in flags:
                report.append(f"    {f}")
        
        # Interesting strings
        if interesting := results.get('strings'):
            for category, items in interesting.items():
                if items:
                    report.append(f"\n[+] {category.upper()}:")
                    for item in items[:5]:
                        report.append(f"    - {item}")
        
        # EXIF
        if exif := results.get('exif'):
            if isinstance(exif, dict) and exif and 'error' not in str(exif):
                report.append(f"\n[+] METADATA:")
                for k, v in list(exif.items())[:10]:
                    report.append(f"    {k}: {str(v)[:60]}")
        
        # Stego
        if stego := results.get('stego'):
            report.append(f"\n[!] STEGANOGRAPHY INDICATORS:")
            for s in stego:
                report.append(f"    - {s}")
        
        report.append(f"\n[*] Output directory: {self.output_dir}")
        report.append(f"{'='*60}")
        
        # Save report
        report_file = os.path.join(self.output_dir, "report.txt")
        with open(report_file, "w") as f:
            f.write("\n".join(report))
        
        return "\n".join(report)

# === MAIN ===
def main():
    log("\n--- Enhanced Forensics Analyzer v2.0 ---\n", "HEADER")
    
    auto_mode = "--auto" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    
    if len(args) < 1:
        log("Usage: ./forensics_analyzer.py <file> [--auto]", "FAIL")
        sys.exit(1)
    
    target = args[0]
    if not os.path.exists(target):
        log(f"[-] File '{target}' not found.", "FAIL")
        sys.exit(1)
    
    log(f"[*] Analyzing: {target}\n", "BOLD")
    
    agent = ForensicsAgent(target)
    
    # Check if memory dump
    mem_analyzer = MemoryAnalyzer(target, agent.output_dir)
    if mem_analyzer.is_memory_dump():
        log("[!] Memory dump detected!", "WARNING")
        os.makedirs(agent.output_dir, exist_ok=True)
        print(mem_analyzer.full_memory_analysis())
    else:
        print(agent.full_analysis())
    
    log("\n[*] Analysis Complete.", "BOLD")

if __name__ == "__main__":
    main()
