#!/usr/bin/env python3

print("""
8    8                                                                                        88                                                                                          
8    8 eeeee e   e eeeee     eeeee  eeee eeeee e  eeeee eeeee eeeee  e    e    eeeee e  eeeee  8 eeeee    e    e eeeee e   e eeeee  eeeee    eeeee eeeee e    e eeeeeee eeeee eeeee  eeee 
8eeee8 8  88 8   8 8   8     8   8  8    8   8 8  8   "   8   8   8  8    8    8   8 8  8   8      8      8    8 8  88 8   8 8   8  8   "    8   8 8   8 8    8 8  8  8 8  88 8   8  8    
  88   8   8 8e  8 8eee8e    8eee8e 8eee 8e    8e 8eeee   8e  8eee8e 8eeee8    8eee8 8e 8e  8      8e     8eeee8 8   8 8e  8 8eee8e 8eeee    8eee8 8e  8 8eeee8 8e 8  8 8   8 8eee8e 8eee 
  88   8   8 88  8 88   8    88   8 88   88 "8 88    88   88  88   8   88      88  8 88 88  8      88       88   8   8 88  8 88   8    88    88  8 88  8   88   88 8  8 8   8 88   8 88   
  88   8eee8 88ee8 88   8    88   8 88ee 88ee8 88 8ee88   88  88   8   88      88  8 88 88  8      88       88   8eee8 88ee8 88   8 8ee88    88  8 88  8   88   88 8  8 8eee8 88   8 88ee 
""")

import os
import sys
import struct
import codecs
import json
from datetime import datetime, timezone

VERSION = "3.0"
MAX_HIVE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB safety limit

# === COLORS ===
COLORS = {
    'GREEN':  '\033[92m',
    'YELLOW': '\033[93m',
    'RED':    '\033[91m',
    'BLUE':   '\033[94m',
    'CYAN':   '\033[96m',
    'BOLD':   '\033[1m',
    'NC':     '\033[0m',
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['NC']}")

# === DEPENDENCY CHECK ===
def check_dependencies():
    log("[*] Checking dependencies...", "BLUE")
    try:
        from Registry import Registry
        log("[✓] All dependencies satisfied!\n", "GREEN")
        return True
    except ImportError:
        log("[✗] MISSING REQUIRED DEPENDENCY:", "RED")
        print("    python-registry")
        print(f"\n{COLORS['YELLOW']}Install with:{COLORS['NC']}")
        print(f"    {COLORS['BOLD']}pip3 install python-registry{COLORS['NC']}\n")
        return False

if not check_dependencies():
    sys.exit(1)

from Registry import Registry


# === HELPERS ===
def filetime_to_dt(filetime_bytes):
    """Convert 8-byte FILETIME to Python datetime."""
    try:
        if len(filetime_bytes) < 8:
            return None
        ft = struct.unpack('<Q', filetime_bytes[:8])[0]
        if ft == 0:
            return None
        # FILETIME epoch: Jan 1, 1601. Unix epoch offset in 100ns intervals.
        EPOCH_DIFF = 116444736000000000
        unix_ts = (ft - EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except Exception:
        return None


# === REGISTRY HUNTER ===
class RegistryHunter:
    def __init__(self, hive_path):
        self.hive_path = hive_path
        self.reg       = Registry.Registry(hive_path)
        self.hive_type = self._identify_hive()
        self.findings  = {}

    def _identify_hive(self):
        checks = [
            ("SAM\\Domains",                                              "SAM"),
            ("Microsoft\\Windows NT\\CurrentVersion",                     "SOFTWARE"),
            ("ControlSet001",                                             "SYSTEM"),
            ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",    "NTUSER.DAT"),
            ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "SOFTWARE"),
        ]
        for path, name in checks:
            if self._key_exists(path):
                return name

        # Fallback: filename hint
        upper = self.hive_path.upper()
        for name in ['NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT']:
            if name in upper:
                return name
        return "UNKNOWN"

    def _key_exists(self, path):
        try:
            self.reg.open(path)
            return True
        except Exception:
            return False

    def _safe_open(self, path):
        try:
            return self.reg.open(path)
        except Exception:
            return None

    def _safe_value(self, key, name):
        try:
            return key.value(name).value()
        except Exception:
            return None

    # ================================================================
    # NTUSER.DAT artifacts
    # ================================================================
    def _parse_userassist(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        key  = self._safe_open(path)
        if not key:
            return []
        results = []
        for guid_key in key.subkeys():
            try:
                count_key = guid_key.subkey("Count")
                for value in count_key.values():
                    decoded = codecs.decode(value.name(), 'rot13')
                    data    = value.value()
                    if len(data) >= 16:
                        run_count = struct.unpack('<I', data[4:8])[0]
                        focus_count = struct.unpack('<I', data[8:12])[0] if len(data) >= 12 else 0
                        results.append({
                            'program':      decoded,
                            'run_count':    run_count,
                            'focus_count':  focus_count,
                        })
            except Exception:
                continue
        return sorted(results, key=lambda x: x['run_count'], reverse=True)[:50]

    def _parse_recent_docs(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        key  = self._safe_open(path)
        if not key:
            return []
        docs = []
        for subkey in key.subkeys():
            try:
                for value in subkey.values():
                    if value.name() == 'MRUListEx':
                        continue
                    raw = value.value()
                    if isinstance(raw, bytes):
                        decoded = raw.decode('utf-16-le', errors='ignore').rstrip('\x00')
                        if decoded:
                            docs.append({'ext': subkey.name(), 'file': decoded})
            except Exception:
                continue
        return docs[:40]

    def _parse_run_mru(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        key  = self._safe_open(path)
        if not key:
            return []
        items = []
        for value in key.values():
            if value.name() not in ('MRUList', 'MRUListEx'):
                try:
                    items.append(value.value())
                except Exception:
                    pass
        return items

    def _parse_typed_paths(self):
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        key  = self._safe_open(path)
        if not key:
            return []
        paths = []
        for value in key.values():
            try:
                paths.append(value.value())
            except Exception:
                pass
        return paths

    def _parse_typed_urls(self):
        path = r"Software\Microsoft\Internet Explorer\TypedURLs"
        key  = self._safe_open(path)
        if not key:
            return []
        urls = []
        for value in key.values():
            try:
                urls.append(value.value())
            except Exception:
                pass
        return urls

    def _parse_run_keys(self):
        """HKCU Run/RunOnce keys — persistence indicators."""
        results = {}
        for sub in [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]:
            key = self._safe_open(sub)
            if not key:
                continue
            entries = {}
            for value in key.values():
                try:
                    entries[value.name()] = value.value()
                except Exception:
                    pass
            if entries:
                results[sub.split('\\')[-1]] = entries
        return results

    def _parse_shellbags(self):
        """BagMRU — explorer folder access history."""
        path = r"Software\Microsoft\Windows\Shell\BagMRU"
        key  = self._safe_open(path)
        if not key:
            return []
        bags = []
        try:
            for value in key.values():
                if value.name() == 'MRUListEx':
                    continue
                raw = value.value()
                if isinstance(raw, bytes) and len(raw) > 2:
                    text = raw.decode('utf-16-le', errors='ignore').rstrip('\x00').strip()
                    if text:
                        bags.append(text)
        except Exception:
            pass
        return bags[:30]

    def _parse_wordwheelquery(self):
        """Search terms typed in Explorer search bar."""
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        key  = self._safe_open(path)
        if not key:
            return []
        terms = []
        for value in key.values():
            if value.name() == 'MRUListEx':
                continue
            try:
                raw = value.value()
                if isinstance(raw, bytes):
                    decoded = raw.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    if decoded:
                        terms.append(decoded)
                else:
                    terms.append(str(raw))
            except Exception:
                pass
        return terms

    def analyze_ntuser(self):
        log("[*] Analyzing NTUSER.DAT...", "CYAN")
        if ua := self._parse_userassist():
            self.findings['UserAssist'] = ua
        if rd := self._parse_recent_docs():
            self.findings['RecentDocs'] = rd
        if rm := self._parse_run_mru():
            self.findings['RunMRU'] = rm
        if tp := self._parse_typed_paths():
            self.findings['TypedPaths'] = tp
        if tu := self._parse_typed_urls():
            self.findings['TypedURLs'] = tu
        if rk := self._parse_run_keys():
            self.findings['RunKeys'] = rk
        if sb := self._parse_shellbags():
            self.findings['Shellbags'] = sb
        if wq := self._parse_wordwheelquery():
            self.findings['SearchTerms'] = wq
        # MUICache (program execution evidence)
        if mc := self._parse_muicache():
            self.findings['MUICache'] = mc
        # RDP connection history
        if rdp := self._parse_rdp_history():
            self.findings['RDP_Connections'] = rdp

    def _parse_muicache(self):
        """MUICache — tracks programs executed by the user."""
        path = r"Software\Microsoft\Windows\ShellNoRoam\MUICache"
        key = self._safe_open(path)
        if not key:
            # Try alternate path for newer Windows
            key = self._safe_open(r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
        if not key:
            return []
        entries = []
        for value in key.values():
            try:
                name = value.name()
                if name and not name.startswith('@') and name != 'LangID':
                    entries.append({'path': name, 'description': value.value()})
            except Exception:
                continue
        return entries[:30]

    def _parse_rdp_history(self):
        """RDP connection history from Terminal Server Client."""
        path = r"Software\Microsoft\Terminal Server Client\Servers"
        key = self._safe_open(path)
        if not key:
            return []
        connections = []
        for server_key in key.subkeys():
            try:
                hostname = server_key.name()
                username = self._safe_value(server_key, "UsernameHint")
                connections.append({
                    'server': hostname,
                    'username': username or 'N/A',
                })
            except Exception:
                continue
        return connections

    # ================================================================
    # SYSTEM hive artifacts
    # ================================================================
    def analyze_system(self):
        log("[*] Analyzing SYSTEM hive...", "CYAN")

        # Current ControlSet
        if sel := self._safe_open("Select"):
            cur = self._safe_value(sel, "Current")
            if cur is not None:
                self.findings['CurrentControlSet'] = f"ControlSet{cur:03d}"

        cs = self.findings.get('CurrentControlSet', 'ControlSet001')

        # Computer name
        cn_key = self._safe_open(f"{cs}\\Control\\ComputerName\\ComputerName")
        if cn_key:
            name = self._safe_value(cn_key, "ComputerName")
            if name:
                self.findings['ComputerName'] = name

        # Timezone
        tz_key = self._safe_open(f"{cs}\\Control\\TimeZoneInformation")
        if tz_key:
            tz = self._safe_value(tz_key, "TimeZoneKeyName")
            if tz:
                self.findings['TimeZone'] = tz

        # USB devices (USBSTOR)
        usb_key = self._safe_open(f"{cs}\\Enum\\USBSTOR")
        if usb_key:
            devices = []
            for class_key in usb_key.subkeys():
                for dev_key in class_key.subkeys():
                    try:
                        friendly = self._safe_value(dev_key, "FriendlyName") or class_key.name()
                        serial   = dev_key.name()
                        ts       = dev_key.timestamp()
                        devices.append({
                            'device': friendly,
                            'serial': serial,
                            'last_seen': str(ts),
                        })
                    except Exception:
                        continue
            if devices:
                self.findings['USB_Devices'] = devices

        # Network interfaces
        nic_key = self._safe_open(f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")
        if nic_key:
            interfaces = {}
            for iface in nic_key.subkeys():
                ip   = self._safe_value(iface, "IPAddress")
                dhcp = self._safe_value(iface, "DhcpIPAddress")
                gw   = self._safe_value(iface, "DefaultGateway")
                if ip or dhcp:
                    interfaces[iface.name()[:36]] = {
                        'IP':      ip,
                        'DHCP_IP': dhcp,
                        'Gateway': gw,
                    }
            if interfaces:
                self.findings['Network_Interfaces'] = interfaces

        # Services (potential persistence)
        svc_key = self._safe_open(f"{cs}\\Services")
        if svc_key:
            suspicious_svcs = []
            for svc in svc_key.subkeys():
                try:
                    img = self._safe_value(svc, "ImagePath")
                    if img and any(x in img.lower() for x in ['temp', 'appdata', 'users\\public', '%tmp%']):
                        suspicious_svcs.append({
                            'name': svc.name(),
                            'path': img,
                        })
                except Exception:
                    continue
            if suspicious_svcs:
                self.findings['Suspicious_Services'] = suspicious_svcs

    # ================================================================
    # SOFTWARE hive artifacts
    # ================================================================
    def analyze_software(self):
        log("[*] Analyzing SOFTWARE hive...", "CYAN")

        # OS version
        os_key = self._safe_open(r"Microsoft\Windows NT\CurrentVersion")
        if os_key:
            fields = ['ProductName', 'DisplayVersion', 'CurrentBuild',
                      'RegisteredOwner', 'RegisteredOrganization', 'InstallDate']
            os_info = {f: self._safe_value(os_key, f) for f in fields if self._safe_value(os_key, f)}
            if os_info:
                self.findings['OS_Info'] = os_info

        # Network profiles (Wi-Fi history)
        net_key = self._safe_open(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
        if net_key:
            networks = []
            for profile in net_key.subkeys():
                name = self._safe_value(profile, "ProfileName")
                cat  = self._safe_value(profile, "Category")
                if name:
                    networks.append({'name': name, 'category': cat})
            if networks:
                self.findings['Network_Profiles'] = networks

        # SYSTEM-wide Run keys
        run_keys = {}
        for sub in [
            r"Microsoft\Windows\CurrentVersion\Run",
            r"Microsoft\Windows\CurrentVersion\RunOnce",
            r"Microsoft\Windows NT\CurrentVersion\Winlogon",
        ]:
            key = self._safe_open(sub)
            if not key:
                continue
            entries = {}
            for value in key.values():
                try:
                    entries[value.name()] = value.value()
                except Exception:
                    pass
            if entries:
                run_keys[sub.split('\\')[-1]] = entries
        if run_keys:
            self.findings['System_RunKeys'] = run_keys

        # Installed software
        uninst_key = self._safe_open(r"Microsoft\Windows\CurrentVersion\Uninstall")
        if uninst_key:
            installed = []
            for app_key in uninst_key.subkeys():
                name = self._safe_value(app_key, "DisplayName")
                ver  = self._safe_value(app_key, "DisplayVersion")
                if name:
                    installed.append({'name': name, 'version': ver})
            if installed:
                self.findings['Installed_Software'] = installed[:40]

    # ================================================================
    # SAM hive artifacts
    # ================================================================
    def analyze_sam(self):
        log("[*] Analyzing SAM hive...", "CYAN")
        path = r"SAM\Domains\Account\Users\Names"
        key  = self._safe_open(path)
        if key:
            users = [subkey.name() for subkey in key.subkeys()]
            if users:
                self.findings['User_Accounts'] = users

    # ================================================================
    # SECURITY hive artifacts
    # ================================================================
    def analyze_security(self):
        log("[*] Analyzing SECURITY hive...", "CYAN")

        # LSA policy information
        pol_key = self._safe_open(r"Policy\PolEKList")
        if pol_key:
            self.findings['LSA_EncryptionKey'] = 'Present (encrypted)'

        # Audit policy
        audit_key = self._safe_open(r"Policy\PolAdtEv")
        if audit_key:
            self.findings['AuditPolicy'] = 'Configured'

        # Cached domain logons
        cache_key = self._safe_open(r"Cache")
        if cache_key:
            cached = []
            for value in cache_key.values():
                try:
                    name = value.name()
                    if name.startswith('NL$') and name != 'NL$Control':
                        raw = value.value()
                        if isinstance(raw, bytes) and len(raw) > 0:
                            # Check if cache entry is populated (non-zero)
                            if any(b != 0 for b in raw[:64]):
                                cached.append(name)
                except Exception:
                    continue
            if cached:
                self.findings['CachedDomainLogons'] = f"{len(cached)} entries found"

    # ================================================================
    # Timeline
    # ================================================================
    def build_timeline(self, depth=2):
        """Recursively collect key timestamps up to `depth` levels."""
        events = []

        def walk(key, current_depth):
            if current_depth > depth:
                return
            try:
                events.append({
                    'timestamp': key.timestamp(),
                    'path':      key.path(),
                })
                for subkey in key.subkeys():
                    walk(subkey, current_depth + 1)
            except Exception:
                pass

        try:
            walk(self.reg.root(), 0)
        except Exception:
            pass

        return sorted(events, key=lambda x: str(x['timestamp']), reverse=True)[:100]

    # ================================================================
    # Main analysis dispatcher
    # ================================================================
    def analyze(self):
        log(f"\n[*] Registry Hive: {self.hive_path}", "BOLD")
        log(f"[*] Hive Type:     {self.hive_type}\n", "BOLD")

        dispatch = {
            "NTUSER.DAT": self.analyze_ntuser,
            "SYSTEM":     self.analyze_system,
            "SOFTWARE":   self.analyze_software,
            "SAM":        self.analyze_sam,
            "SECURITY":   self.analyze_security,
        }

        if fn := dispatch.get(self.hive_type):
            fn()
        else:
            log("[!] Unknown hive type — attempting all parsers", "YELLOW")
            for fn in dispatch.values():
                try:
                    fn()
                except Exception:
                    pass

        return self.findings

    def print_findings(self):
        if not self.findings:
            log("[!] No findings extracted", "YELLOW")
            return
        for category, data in self.findings.items():
            log(f"\n[+] {category}:", "GREEN")
            if isinstance(data, list):
                for item in data[:25]:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            print(f"    {k}: {v}")
                        print()
                    else:
                        print(f"    - {item}")
                if len(data) > 25:
                    print(f"    ... and {len(data) - 25} more")
            elif isinstance(data, dict):
                for k, v in list(data.items())[:25]:
                    if isinstance(v, dict):
                        print(f"    {k}:")
                        for kk, vv in v.items():
                            print(f"        {kk}: {vv}")
                    else:
                        print(f"    {k}: {v}")
            else:
                print(f"    {data}")


# === MAIN ===
def show_help():
    log(f"\n--- Registry Hunter ---\n", "BOLD")
    print("Usage: ./Registry-Hunter.py <hive_file> [options]")
    print("\nOptions:")
    print("  --json            Output results as JSON")
    print("  --timeline        Show key modification timeline")
    print("  --output-dir=DIR  Save reports to directory")
    print("  -h, --help        Show this help")
    print("  -v, --version     Show version")
    print("\nSupported Hive Types:")
    print("  NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY")
    print("\nExamples:")
    print("  ./Registry-Hunter.py NTUSER.DAT")
    print("  ./Registry-Hunter.py SYSTEM --json")
    print("  ./Registry-Hunter.py NTUSER.DAT --timeline")
    print("  ./Registry-Hunter.py SOFTWARE --output-dir=./results")
    sys.exit(0)


def main():
    log(f"\n--- Registry Hunter ---\n", "BOLD")

    if '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    if '-v' in sys.argv or '--version' in sys.argv:
        print(f"Registry-Hunter")
        sys.exit(0)

    if len(sys.argv) < 2:
        log("Usage: ./Registry-Hunter.py <hive_file> [--json] [--timeline]", "RED")
        log("Run './Registry-Hunter.py --help' for full usage.", "CYAN")
        sys.exit(1)

    hive_path     = sys.argv[1]
    json_output   = "--json"     in sys.argv
    show_timeline = "--timeline" in sys.argv
    output_dir    = None

    for arg in sys.argv[2:]:
        if arg.startswith('--output-dir='):
            output_dir = arg.split('=', 1)[1]

    if not os.path.exists(hive_path):
        log(f"[-] File not found: {hive_path}", "RED")
        sys.exit(1)

    if not os.access(hive_path, os.R_OK):
        log(f"[-] Permission denied: {hive_path}", "RED")
        sys.exit(1)

    # File size check
    file_size = os.path.getsize(hive_path)
    if file_size == 0:
        log(f"[-] File is empty: {hive_path}", "RED")
        sys.exit(1)
    if file_size > MAX_HIVE_SIZE:
        log(f"[-] File too large ({file_size / (1024**3):.1f} GB). Max: {MAX_HIVE_SIZE / (1024**3):.0f} GB", "RED")
        sys.exit(1)

    try:
        hunter   = RegistryHunter(hive_path)
        findings = hunter.analyze()

        if json_output:
            output = json.dumps(findings, indent=2, default=str)
            print(output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                json_file = os.path.join(output_dir, f"{os.path.basename(hive_path)}_report.json")
                with open(json_file, 'w') as f:
                    f.write(output)
                log(f"\n[*] JSON saved: {json_file}", "CYAN")
        else:
            hunter.print_findings()

        if show_timeline:
            log("\n[*] Building key modification timeline...", "CYAN")
            timeline = hunter.build_timeline(depth=3)
            if timeline:
                log(f"\n[+] Most Recently Modified Keys (top 20):", "GREEN")
                for event in timeline[:20]:
                    print(f"    [{event['timestamp']}] {event['path']}")

        log("\n[\u2713] Analysis Complete\n", "BOLD")

    except Exception as e:
        log(f"[!] Error: {e}", "RED")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
