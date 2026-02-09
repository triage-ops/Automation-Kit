#!/usr/bin/env python3

print('''
8"""8                                                      8"""88                                 8""""                                                
8   8  eeee ee   e eeee eeeee  eeeee eeee    e eeeee       8    8 e   e  e eeeee    e eeeee       8     e    e eeeee e     eeeee e eeeee    e eeeee    
8eee8e 8    88   8 8    8   8  8   " 8       8   8         8    8 8   8  8 8   8    8   8         8eeee 8    8 8   8 8     8  88 8   8      8   8      
88   8 8eee 88  e8 8eee 8eee8e 8eeee 8eee    8e  8e        8    8 8e  8  8 8e  8    8e  8e        88    eeeeee 8eee8 8e    8   8 8e  8e     8e  8e     
88   8 88    8  8  88   88   8    88 88      88  88        8    8 88  8  8 88  8    88  88        88    88   8 88    88    8   8 88  88     88  88     
88   8 88ee  8ee8  88ee 88   8 8ee88 88ee    88  88  88    8eeee8 88ee8ee8 88  8    88  88  88    88eee 88   8 88    88eee 8eee8 88  88     88  88  88 
                                                                                                                                                       
''')

import os
import sys
import subprocess
import shutil
import re
import hashlib
import struct
import functools
from datetime import datetime

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
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['ENDC']}")

# === DEPENDENCY CHECK ===
REQUIRED_DEPS = {
    'file': 'file',
    'strings': 'binutils',
}

OPTIONAL_DEPS = {
    'objdump': 'binutils',
    'readelf': 'binutils',
    'nm': 'binutils',
    'ltrace': 'ltrace',
    'strace': 'strace',
    'ROPgadget': 'python3-ropgadget',
    'gdb': 'gdb',
}

def check_dependencies():
    """Comprehensive dependency checking"""
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
        for dep in missing_optional[:5]:
            print(f"    {dep}")
        if len(missing_optional) > 5:
            print(f"    ... and {len(missing_optional) - 5} more")
        print()

check_dependencies()

# === REVERSE ENGINEERING AGENT ===
class ReverseEngAgent:
    """Binary analysis with caching and optimizations"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.elf_props = {}
        self.win_functions = []
        self.buffer_overflow_offset = None
        self._strings_cache = None
    
    @functools.lru_cache(maxsize=128)
    def _extract_strings(self, min_len=4):
        """Cached string extraction"""
        try:
            result = subprocess.run(['strings', '-a', '-n', str(min_len), self.filepath],
                                  capture_output=True, text=True, timeout=30)
            return result.stdout.splitlines()
        except:
            # Python fallback
            try:
                with open(self.filepath, 'rb') as f:
                    data = f.read()
                strings = re.findall(rb'[ -~]{%d,}' % min_len, data)
                return [s.decode('utf-8', errors='ignore') for s in strings]
            except:
                return []
    
    @functools.lru_cache(maxsize=32)
    def compute_hashes(self):
        """Compute file hashes with caching"""
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            return {
                'MD5': hashlib.md5(data).hexdigest(),
                'SHA256': hashlib.sha256(data).hexdigest(),
            }
        except:
            return {}
    
    def find_flags(self):
        """Find CTF flags"""
        strings = self._extract_strings(4)
        flags = []
        
        patterns = [
            r'flag\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'thm\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
        ]
        
        for s in strings:
            for pattern in patterns:
                if match := re.search(pattern, s, re.IGNORECASE):
                    flags.append((match.group(), 'FLAG'))
        
        return flags
    
    def analyze_elf(self):
        """Analyze ELF binary"""
        if not shutil.which('readelf'):
            return "readelf not available"
        
        try:
            result = subprocess.run(['readelf', '-h', self.filepath],
                                  capture_output=True, text=True, timeout=10)
            output = result.stdout
            
            # Architecture
            if 'x86-64' in output or 'X86-64' in output:
                self.elf_props['arch'] = 'x86_64'
                self.elf_props['bits'] = 64
            elif 'Intel 80386' in output or 'X86' in output:
                self.elf_props['arch'] = 'i386'
                self.elf_props['bits'] = 32
            elif 'ARM' in output:
                self.elf_props['arch'] = 'arm'
                self.elf_props['bits'] = 32
            elif 'AArch64' in output:
                self.elf_props['arch'] = 'aarch64'
                self.elf_props['bits'] = 64
            
            return f"ELF {self.elf_props.get('bits', 'unknown')}-bit {self.elf_props.get('arch', 'unknown')}"
        except:
            return "ELF analysis failed"
    
    def get_elf_symbols(self):
        """Extract symbol table"""
        if not shutil.which('nm'):
            return []
        
        try:
            result = subprocess.run(['nm', '-D', self.filepath],
                                  capture_output=True, text=True, timeout=10)
            symbols = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    symbols.append(parts[-1])
            return symbols
        except:
            return []
    
    def detect_win_functions(self):
        """Detect potential win/backdoor functions"""
        symbols = self.get_elf_symbols()
        strings = self._extract_strings(3)
        
        win_keywords = [
            'flag', 'win', 'backdoor', 'shell', 'admin', 'secret',
            'hidden', 'debug', 'prize', 'congrat', 'success', 'pwn'
        ]
        
        findings = []
        
        # Check symbols
        for sym in symbols:
            score = 0
            for keyword in win_keywords:
                if keyword in sym.lower():
                    score += 10
            
            if score >= 10:
                # Try to get address
                try:
                    result = subprocess.run(['nm', self.filepath],
                                          capture_output=True, text=True, timeout=5)
                    for line in result.stdout.splitlines():
                        if sym in line:
                            addr = line.split()[0]
                            findings.append((sym, addr, score))
                            break
                except:
                    findings.append((sym, '0x0', score))
        
        # Check strings for function names
        for s in strings[:1000]:
            for keyword in win_keywords:
                if keyword in s.lower() and len(s) < 30:
                    findings.append((s, 'unknown', 5))
                    break
        
        # Sort by score
        findings.sort(key=lambda x: x[2], reverse=True)
        self.win_functions = findings
        return findings
    
    def fuzz_binary(self):
        """Cyclic pattern fuzzing for buffer overflows"""
        log("\n[*] Fuzzing with cyclic pattern...", "WARNING")
        
        # Adaptive pattern length
        file_size = os.path.getsize(self.filepath)
        if file_size < 50 * 1024:
            pattern_len = 500
        elif file_size < 500 * 1024:
            pattern_len = 2000
        else:
            pattern_len = 5000
        
        log(f"    Pattern length: {pattern_len}", "CYAN")
        
        try:
            # Generate De Bruijn sequence
            from string import ascii_lowercase
            alphabet = ascii_lowercase
            n = 4
            
            pattern = ""
            a = [0] * n * len(alphabet)
            sequence = []
            
            def db(t, p):
                if t > n:
                    if n % p == 0:
                        sequence.extend(a[1:p + 1])
                else:
                    a[t] = a[t - p]
                    db(t + 1, p)
                    for j in range(a[t - p] + 1, len(alphabet)):
                        a[t] = j
                        db(t + 1, t)
            
            db(1, 1)
            pattern = ''.join(alphabet[i] for i in sequence)
            pattern = (pattern * (pattern_len // len(pattern) + 1))[:pattern_len]
            
            # Save pattern
            with open('/tmp/pattern.txt', 'w') as f:
                f.write(pattern)
            
            # Run with pattern
            proc = subprocess.run(f"timeout 3s {self.filepath} < /tmp/pattern.txt",
                                shell=True, capture_output=True)
            
            # Check for crash
            if proc.returncode != 0:
                log("    [!] Crash detected!", "WARNING")
                
                # Try to find offset from dmesg
                try:
                    dmesg = subprocess.run(['dmesg'], capture_output=True, text=True)
                    for line in dmesg.stdout.splitlines()[-20:]:
                        if 'segfault' in line.lower():
                            if match := re.search(r'ip ([0-9a-f]+)', line):
                                crash_addr = match.group(1)
                                log(f"    Crash at: 0x{crash_addr}", "FAIL")
                                
                                # Find offset
                                crash_pattern = bytes.fromhex(crash_addr)
                                if crash_pattern in pattern.encode():
                                    offset = pattern.encode().index(crash_pattern)
                                    log(f"    [!!!] Buffer overflow offset: {offset}", "GREEN")
                                    self.buffer_overflow_offset = offset
                                    return offset
                except:
                    pass
        except Exception as e:
            log(f"    Fuzzing error: {e}", "FAIL")
        
        return None
    
    def find_rop_gadgets(self):
        """Find ROP gadgets"""
        log("\n[*] Searching for ROP gadgets...", "CYAN")
        
        for tool in ['ROPgadget', 'ropper']:
            if shutil.which(tool):
                try:
                    cmd = [tool, '--binary', self.filepath] if tool == 'ROPgadget' else [tool, '--file', self.filepath, '--search', 'pop']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    gadgets = []
                    for line in result.stdout.splitlines()[:20]:  # First 20
                        if 'pop' in line.lower() or 'ret' in line.lower():
                            gadgets.append(line.strip())
                            log(f"    {line.strip()}", "BLUE")
                    
                    return gadgets
                except:
                    pass
        
        log("    ROPgadget/ropper not found", "WARNING")
        return []
    
    def generate_exploit_script(self):
        """Generate pwntools exploit template"""
        log("\n[*] Generating exploit template...", "GREEN")
        
        script = f"""#!/usr/bin/env python3
from pwn import *

# === Target Configuration ===
binary = './{self.filename}'
host = 'localhost'
port = 1337

# === Context Setup ===
elf = context.binary = ELF(binary)
context.arch = '{self.elf_props.get('arch', 'i386')}'
context.bits = {self.elf_props.get('bits', 32)}
context.log_level = 'debug'

# === Discovered Information ===
"""
        
        if self.buffer_overflow_offset:
            script += f"offset = {self.buffer_overflow_offset}  # Buffer overflow offset\n"
        
        if self.win_functions:
            script += "\n# Win functions found:\n"
            for func, addr, score in self.win_functions[:3]:
                script += f"# {func} @ {addr} (score: {score})\n"
                if addr != 'unknown' and addr != '0x0':
                    script += f"{func.replace('-', '_').replace('.', '_')} = {addr}\n"
        
        script += """
# === Exploit ===
def exploit():
    # Choose connection method
    if args.REMOTE:
        io = remote(host, port)
    else:
        io = process(binary)
    
    # === Build payload ===
"""
        
        if self.buffer_overflow_offset:
            script += f"""    payload = b'A' * {self.buffer_overflow_offset}
    # payload += p{self.elf_props.get('bits', 32)}(win_function_address)
    
    io.sendline(payload)
"""
        else:
            script += """    # Add your exploit here
    payload = b'TODO'
    io.sendline(payload)
"""
        
        script += """    
    # === Interact ===
    io.interactive()

if __name__ == '__main__':
    exploit()
"""
        
        # Save script
        exploit_file = f"exploit_{self.filename}.py"
        with open(exploit_file, 'w') as f:
            f.write(script)
        
        os.chmod(exploit_file, 0o755)
        log(f"[+] Exploit template saved: {exploit_file}", "GREEN")
    
    def auto_analyze_static(self):
        """Run full static analysis"""
        report = []
        
        report.append(f"[*] HASHES:")
        hashes = self.compute_hashes()
        for algo, h in hashes.items():
            report.append(f"    {algo}: {h}")
        
        # Format
        with open(self.filepath, 'rb') as f:
            header = f.read(4)
        
        if header.startswith(b'\x7fELF'):
            fmt = self.analyze_elf()
            report.append(f"\n[*] FORMAT: {fmt}")
        elif header.startswith(b'MZ'):
            report.append(f"\n[*] FORMAT: PE Executable")
        
        # Flags
        flags = self.find_flags()
        if flags:
            report.append("\n[+] FLAGS FOUND:")
            for flag, tag in flags:
                report.append(f"    - {flag}")
        
        # Win functions
        win_funcs = self.detect_win_functions()
        if win_funcs:
            report.append(f"\n[!!!] WIN FUNCTIONS ({len(win_funcs)}):")
            for func, addr, score in win_funcs[:10]:
                if score >= 10:
                    report.append(f"    - {COLORS['GREEN']}{func} @ {addr} [SCORE: {score}]{COLORS['ENDC']}")
                else:
                    report.append(f"    - {func} @ {addr} [SCORE: {score}]")
        
        # Symbols
        symbols = self.get_elf_symbols()
        interesting = [s for s in symbols if any(k in s.lower() for k in ['main', 'flag', 'check', 'auth'])]
        if interesting:
            report.append(f"\n[+] INTERESTING SYMBOLS:")
            for s in interesting[:10]:
                report.append(f"    - {s}")
        
        return "\n".join(report), []

# === MAIN ===
def main():
    log("\n--- Enhanced Reverse Engineering Tool v2.0 ---\n", "HEADER")
    
    if len(sys.argv) < 2:
        log("Usage: ./reverse_engineer.py <binary> [--auto|--fuzz]", "FAIL")
        sys.exit(1)
    
    target = sys.argv[1] if not sys.argv[1].startswith('-') else sys.argv[2] if len(sys.argv) > 2 else None
    
    if not target or not os.path.exists(target):
        log(f"[-] File not found", "FAIL")
        sys.exit(1)
    
    auto_mode = "--auto" in sys.argv
    fuzz_mode = "--fuzz" in sys.argv
    
    log(f"[*] Analyzing: {target}\n", "BOLD")
    
    agent = ReverseEngAgent(target)
    
    if fuzz_mode:
        agent.analyze_elf()
        agent.fuzz_binary()
        sys.exit(0)
    
    # Static analysis
    log("--- Static Analysis ---", "HEADER")
    static_report, _ = agent.auto_analyze_static()
    print(static_report)
    
    # Exploitation recon
    if auto_mode:
        log("\n--- Exploitation Recon ---", "HEADER")
        agent.find_rop_gadgets()
        
        offset = agent.fuzz_binary()
        
        if offset or agent.win_functions:
            agent.generate_exploit_script()
    
    log("\n[*] Analysis Complete.", "BOLD")

if __name__ == "__main__":
    main()
