#!/usr/bin/env python3

print('''
8"""""8                                                      8"""""8                                 8""""                                                
8   8  eeee ee   e eeee eeeee  eeeee eeee    e eeeee        8    8 e   e  e eeeee    e eeeee         8     e    e eeeee e     eeeee e eeeee    e eeeee    
8eee8e 8    88   8 8    8   8  8   " 8       8   8          8    8 8   8  8 8   8    8   8            8eeee 8    8 8   8 8     8  88 8   8      8   8      
88   8 8eee 88  e8 8eee 8eee8e 8eeee 8eee    8e  8e         8    8 8e  8  8 8e  8    8e  8e           88    eeeeee 8eee8 8e    8   8 8e  8e     8e  8e     
88   8 88    8  8  88   88   8    88 88      88  88         8    8 88  8  8 88  8    88  88           88    88   8 88    88    8   8 88  88     88  88     
88   8 88ee  8ee8  88ee 88   8 8ee88 88ee    88  88  88     8eeee8 88ee8ee8 88  8    88  88  88       88eee 88   8 88    88eee 8eee8 88  88     88  88  88 
''')

import os
import sys
import subprocess
import shutil
import re
import hashlib
import struct
import tempfile
import functools
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "3.0"

# === COLORS ===
COLORS = {
    'HEADER':  '\033[95m',
    'BLUE':    '\033[94m',
    'CYAN':    '\033[96m',
    'GREEN':   '\033[92m',
    'WARNING': '\033[93m',
    'FAIL':    '\033[91m',
    'ENDC':    '\033[0m',
    'BOLD':    '\033[1m',
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['ENDC']}")

# === DEPENDENCY CHECK ===
REQUIRED_DEPS = {
    'file':    'file',
    'strings': 'binutils',
}

OPTIONAL_DEPS = {
    'objdump':    'binutils',
    'readelf':    'binutils',
    'nm':         'binutils',
    'ltrace':     'ltrace',
    'strace':     'strace',
    'ROPgadget':  'python3-ropgadget',
    'ropper':     'ropper',
    'gdb':        'gdb',
    'r2':         'radare2',
    'pwndbg':     'pwndbg',
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
        packages = list(set(REQUIRED_DEPS.values()))
        print(f"\n{COLORS['WARNING']}Install with:{COLORS['ENDC']}")
        print(f"    {COLORS['BOLD']}sudo apt install {' '.join(packages)}{COLORS['ENDC']}\n")
        sys.exit(1)

    if missing_optional:
        log("[!] Missing optional tools:", "WARNING")
        for dep in missing_optional[:6]:
            print(f"    {dep}")
        if len(missing_optional) > 6:
            print(f"    ... and {len(missing_optional) - 6} more")
        print()

check_dependencies()


# === REVERSE ENGINEERING AGENT ===
class ReverseEngAgent:

    def __init__(self, filepath):
        self.filepath   = filepath
        self.filename   = os.path.basename(filepath)
        self.filesize   = os.path.getsize(filepath)
        self.elf_props  = {}
        self.win_functions = []
        self.buffer_overflow_offset = None
        self._strings_cache = {}

    def _extract_strings(self, min_len=4):
        if min_len in self._strings_cache:
            return self._strings_cache[min_len]
        try:
            result = subprocess.run(
                ['strings', '-a', '-n', str(min_len), self.filepath],
                capture_output=True, text=True, timeout=30
            )
            strings = result.stdout.splitlines()
        except Exception:
            # Python fallback
            try:
                with open(self.filepath, 'rb') as f:
                    data = f.read()
                matches = re.findall(rb'[ -~]{%d,}' % min_len, data)
                strings = [m.decode('utf-8', errors='ignore') for m in matches]
            except Exception:
                strings = []
        self._strings_cache[min_len] = strings
        return strings

    def compute_hashes(self):
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            return {
                'MD5':    hashlib.md5(data).hexdigest(),
                'SHA256': hashlib.sha256(data).hexdigest(),
                'SHA1':   hashlib.sha1(data).hexdigest(),
            }
        except Exception:
            return {}

    def find_flags(self):
        strings = self._extract_strings(4)
        patterns = [
            r'flag\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'thm\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
            r'dice\{[^}]+\}',
            r'ductf\{[^}]+\}',
        ]
        found = []
        for s in strings:
            for pattern in patterns:
                if m := re.search(pattern, s, re.IGNORECASE):
                    found.append((m.group(), 'FLAG'))
        return list({f[0]: f for f in found}.values())  # deduplicate

    def analyze_elf(self):
        if not shutil.which('readelf'):
            return "readelf not available"
        try:
            result = subprocess.run(
                ['readelf', '-h', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            out = result.stdout

            if 'x86-64' in out or 'X86-64' in out:
                self.elf_props.update({'arch': 'x86_64', 'bits': 64})
            elif 'Intel 80386' in out:
                self.elf_props.update({'arch': 'i386',   'bits': 32})
            elif 'AArch64' in out:
                self.elf_props.update({'arch': 'aarch64','bits': 64})
            elif 'ARM' in out:
                self.elf_props.update({'arch': 'arm',    'bits': 32})
            elif 'MIPS' in out:
                self.elf_props.update({'arch': 'mips',   'bits': 32})
            elif 'RISC-V' in out:
                self.elf_props.update({'arch': 'riscv',  'bits': 64})

            # Entry point
            if m := re.search(r'Entry point address:\s+(0x[0-9a-fA-F]+)', out):
                self.elf_props['entry'] = m.group(1)

            # Type: EXEC vs DYN (PIE)
            if m := re.search(r'Type:\s+(\w+)', out):
                self.elf_props['type'] = m.group(1)

            return f"ELF {self.elf_props.get('bits', '?')}-bit {self.elf_props.get('arch', '?')}"
        except Exception as e:
            return f"ELF analysis failed: {e}"

    def get_elf_symbols(self):
        if not shutil.which('nm'):
            return []
        try:
            result = subprocess.run(
                ['nm', '-D', '--defined-only', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            symbols = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    symbols.append({'addr': parts[0], 'type': parts[1], 'name': parts[-1]})
            return symbols
        except Exception:
            return []

    def get_plt_got(self):
        """Extract PLT/GOT entries to identify imported libc functions."""
        if not shutil.which('objdump'):
            return []
        try:
            result = subprocess.run(
                ['objdump', '-d', '-j', '.plt', self.filepath],
                capture_output=True, text=True, timeout=15
            )
            imports = re.findall(r'<(.+?)@plt>', result.stdout)
            return list(set(imports))
        except Exception:
            return []

    def check_protections(self):
        """Check ELF security mitigations."""
        protections = {}
        if not shutil.which('readelf'):
            return protections

        try:
            # NX
            prog = subprocess.run(
                ['readelf', '-l', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            if 'GNU_STACK' in prog.stdout:
                line = next((l for l in prog.stdout.splitlines() if 'GNU_STACK' in l), '')
                protections['NX'] = 'Disabled (RWX stack)' if 'RWE' in line or 'E' in line.split()[-1:] else 'Enabled'
            else:
                protections['NX'] = 'Unknown'

            # PIE
            hdr = subprocess.run(
                ['readelf', '-h', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            if 'Type:' in hdr.stdout:
                t = next((l for l in hdr.stdout.splitlines() if 'Type:' in l), '')
                if 'EXEC' in t:
                    protections['PIE'] = 'Disabled'
                elif 'DYN' in t:
                    protections['PIE'] = 'Enabled'

            # Canary
            sym = subprocess.run(
                ['nm', '-D', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            protections['Canary'] = 'Present' if '__stack_chk_fail' in sym.stdout else 'Absent'

            # RELRO
            dyn = subprocess.run(
                ['readelf', '-d', self.filepath],
                capture_output=True, text=True, timeout=10
            )
            if 'BIND_NOW' in dyn.stdout:
                protections['RELRO'] = 'Full'
            elif 'GNU_RELRO' in prog.stdout:
                protections['RELRO'] = 'Partial'
            else:
                protections['RELRO'] = 'None'

        except Exception:
            pass

        return protections

    def detect_win_functions(self):
        symbols  = self.get_elf_symbols()
        strings  = self._extract_strings(3)
        win_kw   = ['flag', 'win', 'backdoor', 'shell', 'admin', 'secret',
                    'hidden', 'debug', 'prize', 'congrat', 'success', 'pwn',
                    'give', 'print_flag', 'get_flag']
        findings = []

        for sym in symbols:
            name  = sym['name']
            addr  = sym['addr']
            score = 0
            for kw in win_kw:
                if kw in name.lower():
                    score += 10
            if score >= 10:
                findings.append({'name': name, 'addr': addr, 'score': score, 'source': 'symbol'})

        # Also check interesting strings
        for s in strings[:2000]:
            if any(kw in s.lower() for kw in win_kw) and 4 < len(s) < 40:
                findings.append({'name': s, 'addr': 'unknown', 'score': 5, 'source': 'string'})

        findings.sort(key=lambda x: x['score'], reverse=True)
        self.win_functions = findings
        return findings

    def detect_vulnerable_functions(self):
        """Detect dangerous C functions in the binary."""
        dangerous = {
            'gets':     ('CRITICAL', 'Unbounded read — guaranteed buffer overflow'),
            'strcpy':   ('HIGH',     'No bounds checking — buffer overflow risk'),
            'strcat':   ('HIGH',     'No bounds checking — buffer overflow risk'),
            'sprintf':  ('HIGH',     'No bounds checking — buffer overflow risk'),
            'vsprintf': ('HIGH',     'No bounds checking — buffer overflow risk'),
            'scanf':    ('MEDIUM',   'Possible format string / overflow'),
            'gets_s':   ('LOW',      'Bounded but deprecated'),
            'mktemp':   ('MEDIUM',   'Race condition risk'),
            'tmpnam':   ('MEDIUM',   'Race condition risk'),
        }
        found = {}
        symbols = self.get_elf_symbols()
        plt     = self.get_plt_got()
        all_names = [s['name'] for s in symbols] + plt

        for name in all_names:
            if name in dangerous:
                severity, desc = dangerous[name]
                found[name] = (severity, desc)

        return found

    def detect_format_string_vulns(self):
        """Detect potential format string vulnerabilities."""
        if not shutil.which('objdump'):
            return []
        findings = []
        try:
            # Look for printf-family calls without format string
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.filepath],
                capture_output=True, text=True, timeout=20
            )
            lines = result.stdout.splitlines()
            printf_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'syslog']
            for i, line in enumerate(lines):
                for func in printf_funcs:
                    if f'<{func}@plt>' in line or f'<{func}>' in line:
                        # Check if previous instruction loads format from user input
                        context = lines[max(0, i-5):i+1]
                        context_str = ' '.join(context)
                        if 'mov' in context_str and ('rdi' in context_str or 'edi' in context_str):
                            # Simple heuristic: if no hardcoded string ref before call
                            if not any('0x' in l and 'lea' in l for l in context):
                                findings.append(f"Potential format string at {line.strip()[:60]}")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return findings[:10]

    def detect_libc_version(self):
        """Try to detect linked libc version."""
        strings = self._extract_strings(6)
        for s in strings:
            if 'GLIBC_' in s:
                versions = re.findall(r'GLIBC_(\d+\.\d+)', s)
                if versions:
                    return max(versions, key=lambda v: tuple(int(x) for x in v.split('.')))
            if 'GNU C Library' in s:
                if m := re.search(r'(\d+\.\d+)', s):
                    return m.group(1)
        return None

    def decompile_main(self):
        """Dump disassembly of main (or entry) via objdump."""
        if not shutil.which('objdump'):
            return ""
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', self.filepath],
                capture_output=True, text=True, timeout=20
            )
            # Extract main() block
            lines   = result.stdout.splitlines()
            in_main = False
            main_asm = []
            for line in lines:
                if re.match(r'[0-9a-f]+ <(main|_start)>:', line):
                    in_main = True
                if in_main:
                    main_asm.append(line)
                    if len(main_asm) > 60:  # cap at 60 instructions
                        main_asm.append("    ...")
                        break
                if in_main and line == '':
                    break
            return '\n'.join(main_asm)
        except Exception:
            return ""

    def fuzz_binary(self, skip_confirm=False):
        """Cyclic De Bruijn pattern fuzzing using a secure temp file."""
        # Safety: confirm before executing untrusted binary
        if not skip_confirm:
            print(f"\n{COLORS['WARNING']}[!] WARNING: Fuzzing will EXECUTE the binary: {self.filepath}{COLORS['ENDC']}")
            try:
                confirm = input(f"{COLORS['WARNING']}    Proceed? [y/N]: {COLORS['ENDC']}").strip().lower()
                if confirm != 'y':
                    log("    Fuzzing cancelled", "CYAN")
                    return None
            except (EOFError, KeyboardInterrupt):
                log("\n    Fuzzing cancelled", "CYAN")
                return None

        log("\n[*] Fuzzing with cyclic De Bruijn pattern...", "WARNING")

        file_size = self.filesize
        if file_size < 50 * 1024:
            pattern_len = 600
        elif file_size < 500 * 1024:
            pattern_len = 3000
        else:
            pattern_len = 8000
        log(f"    Pattern length: {pattern_len}", "CYAN")

        # Generate De Bruijn sequence
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        n = 4
        seq = []
        a   = [0] * (n * len(alphabet))

        def db(t, p):
            if t > n:
                if n % p == 0:
                    seq.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, len(alphabet)):
                    a[t] = j
                    db(t + 1, t)

        db(1, 1)
        raw     = ''.join(alphabet[i] for i in seq)
        pattern = (raw * (pattern_len // len(raw) + 1))[:pattern_len]

        try:
            # Use a named temp file in /tmp — auto-cleaned on close
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pat', delete=False) as pf:
                pf.write(pattern)
                pat_path = pf.name

            proc = subprocess.run(
                ['timeout', '3s', self.filepath],
                stdin=open(pat_path, 'rb'),
                capture_output=True
            )

            if proc.returncode not in (0, 1):  # crash
                log(f"    [!] Crash detected! Return code: {proc.returncode}", "WARNING")

                # Try to find crash address via dmesg
                try:
                    dmesg = subprocess.run(['dmesg'], capture_output=True, text=True)
                    for line in reversed(dmesg.stdout.splitlines()[-30:]):
                        if 'segfault' in line.lower():
                            if m := re.search(r'ip ([0-9a-f]+)', line):
                                crash_addr = m.group(1)
                                log(f"    Crash at: 0x{crash_addr}", "FAIL")
                                # Find offset in pattern
                                try:
                                    crash_bytes = bytes.fromhex(crash_addr.zfill(8))
                                    if crash_bytes in pattern.encode():
                                        offset = pattern.encode().index(crash_bytes)
                                        log(f"    [!!!] Buffer overflow offset: {offset}", "GREEN")
                                        self.buffer_overflow_offset = offset
                                        return offset
                                except Exception:
                                    pass
                            break
                except Exception:
                    pass
            else:
                log("    No crash detected with this pattern length", "CYAN")

        except Exception as e:
            log(f"    Fuzzing error: {e}", "FAIL")
        finally:
            try:
                os.unlink(pat_path)
            except Exception:
                pass

        return None

    def find_rop_gadgets(self):
        log("\n[*] Searching for ROP gadgets...", "CYAN")

        for tool, args in [
            ('ROPgadget', ['--binary', self.filepath, '--rop', '--nojop']),
            ('ropper',    ['--file',   self.filepath, '--search', 'pop']),
        ]:
            if shutil.which(tool):
                try:
                    result = subprocess.run(
                        [tool] + args,
                        capture_output=True, text=True, timeout=30
                    )
                    gadgets = []
                    for line in result.stdout.splitlines():
                        low = line.lower()
                        if any(k in low for k in ['pop', 'ret', 'leave', 'syscall']):
                            gadgets.append(line.strip())
                            log(f"    {line.strip()}", "BLUE")
                        if len(gadgets) >= 25:
                            break
                    if gadgets:
                        return gadgets
                except Exception:
                    pass

        log("    ROPgadget/ropper not found", "WARNING")
        return []

    def generate_exploit_script(self):
        log("\n[*] Generating exploit template...", "GREEN")

        arch = self.elf_props.get('arch', 'i386')
        bits = self.elf_props.get('bits', 32)
        pie  = self.elf_props.get('type', '') == 'DYN'
        plt  = self.get_plt_got()

        script = f"""#!/usr/bin/env python3
# Auto-generated by Reverse-Engineer.py
# Target: {self.filename}

from pwn import *

# === Target Config ===
binary   = ELF('./{self.filename}', checksec=True)
rop      = ROP(binary)
host, port = 'localhost', 1337

# === Context ===
context.arch      = '{arch}'
context.bits      = {bits}
context.log_level = 'debug'
context.binary    = binary

"""
        if pie:
            script += "# PIE binary — leak base before jumping to gadgets\nbase = binary.address\n\n"

        if self.buffer_overflow_offset:
            script += f"OFFSET = {self.buffer_overflow_offset}  # confirmed overflow offset\n\n"

        if self.win_functions:
            script += "# Win functions detected:\n"
            for fn in self.win_functions[:5]:
                if fn['addr'] != 'unknown':
                    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', fn['name'])
                    script += f"{safe_name} = {fn['addr']}  # score: {fn['score']}\n"
            script += "\n"

        if plt:
            script += "# PLT imports (useful for ret2libc):\n"
            for fn in plt[:10]:
                script += f"# {fn}\n"
            script += "\n"

        script += f"""
def exploit(local=True):
    if local:
        io = process('./{self.filename}')
        # io = gdb.debug('./{self.filename}', '''
        #     break main
        #     continue
        # ''')
    else:
        io = remote(host, port)

    # === Build payload ===
"""
        if self.buffer_overflow_offset:
            script += f"""    payload  = flat(
        b'A' * OFFSET,
        # TODO: fill_return_address_here
    )
    io.sendlineafter(b':', payload)
"""
        else:
            script += """    payload = b'TODO'
    io.sendline(payload)
"""
        script += """
    io.interactive()

if __name__ == '__main__':
    exploit(local='--remote' not in sys.argv)
"""

        exploit_file = f"exploit_{self.filename}.py"
        with open(exploit_file, 'w') as f:
            f.write(script)
        os.chmod(exploit_file, 0o755)

        # Also generate a GDB helper script
        gdb_script = f"""# GDB helper for {self.filename}
# Run: gdb -x gdb_{self.filename}.gdb ./{self.filename}
set disassembly-flavor intel
set follow-fork-mode child
set disable-randomization on
break main
"""
        if self.buffer_overflow_offset:
            gdb_script += f"\n# Overflow offset: {self.buffer_overflow_offset}\n"
        if self.win_functions:
            for fn in self.win_functions[:3]:
                if fn['addr'] != 'unknown':
                    gdb_script += f"# Win: {fn['name']} @ {fn['addr']}\n"
        gdb_script += "\nrun\n"

        gdb_file = f"gdb_{self.filename}.gdb"
        with open(gdb_file, 'w') as f:
            f.write(gdb_script)

        log(f"[+] Exploit template: {exploit_file}", "GREEN")
        log(f"[+] GDB script:       {gdb_file}", "GREEN")

    def auto_analyze_static(self):
        report = []

        # Hashes
        hashes = self.compute_hashes()
        report.append("[*] HASHES:")
        for algo, h in hashes.items():
            report.append(f"    {algo}: {h}")

        # Format / arch
        with open(self.filepath, 'rb') as f:
            header = f.read(4)

        if header.startswith(b'\x7fELF'):
            fmt = self.analyze_elf()
            report.append(f"\n[*] FORMAT: {fmt}")
        elif header.startswith(b'MZ'):
            report.append(f"\n[*] FORMAT: PE Executable")

        # Protections
        if header.startswith(b'\x7fELF'):
            prots = self.check_protections()
            if prots:
                report.append("\n[*] SECURITY PROTECTIONS:")
                colors = {
                    'Enabled': COLORS['GREEN'], 'Present': COLORS['GREEN'],
                    'Full': COLORS['GREEN'],    'Partial': COLORS['WARNING'],
                    'Disabled': COLORS['FAIL'], 'Absent': COLORS['FAIL'],
                    'None': COLORS['FAIL'],
                }
                for k, v in prots.items():
                    c = colors.get(v, '')
                    report.append(f"    {k}: {c}{v}{COLORS['ENDC']}")

        # PLT imports
        plt_fns = self.get_plt_got()
        if plt_fns:
            report.append(f"\n[+] PLT IMPORTS ({len(plt_fns)}):")
            for fn in plt_fns[:15]:
                report.append(f"    - {fn}")

        # Flags
        flags = self.find_flags()
        if flags:
            report.append("\n[+] FLAGS FOUND:")
            for flag, _ in flags:
                report.append(f"    - {COLORS['GREEN']}{flag}{COLORS['ENDC']}")

        # Vulnerable functions
        vuln_funcs = self.detect_vulnerable_functions()
        if vuln_funcs:
            report.append(f"\n[!!!] VULNERABLE FUNCTIONS ({len(vuln_funcs)}):")
            for func, (severity, desc) in vuln_funcs.items():
                color = COLORS['FAIL'] if severity == 'CRITICAL' else COLORS['WARNING']
                report.append(f"    - {color}{func}() [{severity}]{COLORS['ENDC']}: {desc}")

        # Format string vulns
        fmt_vulns = self.detect_format_string_vulns()
        if fmt_vulns:
            report.append(f"\n[!!!] POTENTIAL FORMAT STRING VULNERABILITIES:")
            for v in fmt_vulns:
                report.append(f"    - {v}")

        # Libc version
        libc_ver = self.detect_libc_version()
        if libc_ver:
            report.append(f"\n[+] GLIBC VERSION: {libc_ver}")
            # one_gadget suggestion
            report.append(f"    Tip: run 'one_gadget /lib/x86_64-linux-gnu/libc.so.6' for magic gadgets")

        # Win functions
        win_funcs = self.detect_win_functions()
        if win_funcs:
            report.append(f"\n[!!!] WIN/INTERESTING FUNCTIONS ({len(win_funcs)}):")
            for fn in win_funcs[:12]:
                if fn['score'] >= 10:
                    c = COLORS['GREEN']
                else:
                    c = COLORS['CYAN']
                report.append(f"    - {c}{fn['name']} @ {fn['addr']} [score: {fn['score']}]{COLORS['ENDC']}")

        # Symbols
        symbols  = self.get_elf_symbols()
        kw_syms  = [s['name'] for s in symbols if any(k in s['name'].lower() for k in ['main', 'flag', 'check', 'auth', 'verify', 'compare', 'cmp'])]
        if kw_syms:
            report.append(f"\n[+] INTERESTING SYMBOLS:")
            for s in kw_syms[:12]:
                report.append(f"    - {s}")

        # Main disassembly
        if header.startswith(b'\x7fELF') and shutil.which('objdump'):
            asm = self.decompile_main()
            if asm:
                report.append(f"\n[+] MAIN DISASSEMBLY (Intel):")
                for line in asm.splitlines()[:40]:
                    report.append(f"    {line}")

        return "\n".join(report), []


# === MAIN ===
def show_help():
    log(f"\n--- Reverse Engineering Tool ---\n", "HEADER")
    print("Usage: ./Reverse-Engineer.py <binary> [options]")
    print("\nOptions:")
    print("  --auto    Full auto analysis (static + fuzz + rop + exploit gen)")
    print("  --fuzz    Fuzz the binary with cyclic patterns")
    print("  --rop     Search for ROP gadgets")
    print("  -h, --help     Show this help")
    print("  -v, --version  Show version")
    print("\nExamples:")
    print("  ./Reverse-Engineer.py ./vuln_binary")
    print("  ./Reverse-Engineer.py ./pwn_challenge --auto")
    print("  ./Reverse-Engineer.py ./binary --fuzz --rop")
    sys.exit(0)


def main():
    log(f"\n--- Reverse Engineering Tool ---\n", "HEADER")

    if '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    if '-v' in sys.argv or '--version' in sys.argv:
        print(f"Reverse-Engineer")
        sys.exit(0)

    if len(sys.argv) < 2:
        log("Usage: ./Reverse-Engineer.py <binary> [--auto] [--fuzz] [--rop]", "FAIL")
        log("Run './Reverse-Engineer.py --help' for full usage.", "CYAN")
        sys.exit(1)

    # Accept target as first non-flag arg
    targets = [a for a in sys.argv[1:] if not a.startswith('--')]
    if not targets:
        log("[-] No target file specified", "FAIL")
        sys.exit(1)

    target    = targets[0]
    auto_mode = "--auto" in sys.argv
    fuzz_mode = "--fuzz" in sys.argv
    rop_mode  = "--rop"  in sys.argv

    if not os.path.exists(target):
        log(f"[-] File not found: {target}", "FAIL")
        sys.exit(1)

    if not os.access(target, os.R_OK):
        log(f"[-] Permission denied: {target}", "FAIL")
        sys.exit(1)

    log(f"[*] Analyzing: {target}\n", "BOLD")

    agent = ReverseEngAgent(target)

    # Always run static analysis
    log("--- Static Analysis ---", "HEADER")
    static_report, _ = agent.auto_analyze_static()
    print(static_report)

    if fuzz_mode:
        log("\n--- Fuzzing ---", "HEADER")
        agent.analyze_elf()
        agent.fuzz_binary(skip_confirm=auto_mode)

    if rop_mode or auto_mode:
        log("\n--- Exploitation Recon ---", "HEADER")
        agent.find_rop_gadgets()

        if not fuzz_mode and auto_mode:
            agent.fuzz_binary(skip_confirm=True)

        if agent.buffer_overflow_offset is not None or agent.win_functions:
            agent.generate_exploit_script()

    log("\n[*] Analysis Complete.", "BOLD")


if __name__ == "__main__":
    main()
