#!/usr/bin/env python3

print ("""
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
from datetime import datetime

# === COLORS ===
COLORS = {
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'BOLD': '\033[1m',
    'NC': '\033[0m',
}

def log(msg, color='BLUE'):
    print(f"{COLORS.get(color, '')}{msg}{COLORS['NC']}")

# === DEPENDENCY CHECK ===
def check_dependencies():
    """Check for python-registry library"""
    log("[*] Checking dependencies...", "BLUE")
    
    try:
        from Registry import Registry
        log("[✓] All dependencies satisfied!\n", "GREEN")
        return True
    except ImportError:
        log("[✗] MISSING REQUIRED DEPENDENCY:", "RED")
        print("    python-registry (python-registry)")
        print(f"\n{COLORS['YELLOW']}Install with:{COLORS['NC']}")
        print(f"    {COLORS['BOLD']}pip3 install python-registry{COLORS['NC']}\n")
        return False

if not check_dependencies():
    sys.exit(1)

from Registry import Registry

# === REGISTRY HUNTER ===
class RegistryHunter:
    """Extract forensic artifacts from Windows registry hives"""
    
    def __init__(self, hive_path):
        self.hive_path = hive_path
        self.reg = Registry.Registry(hive_path)
        self.hive_type = self.identify_hive()
        self.findings = {}
    
    def identify_hive(self):
        """Identify hive type"""
        try:
            # Try known paths
            if self._key_exists("SAM\\Domains"):
                return "SAM"
            if self._key_exists("Microsoft\\Windows NT\\CurrentVersion"):
                return "SOFTWARE"
            if self._key_exists("ControlSet001"):
                return "SYSTEM"
            if self._key_exists("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"):
                return "NTUSER.DAT"
        except:
            pass
        
        # Fallback heuristic
        if 'NTUSER' in self.hive_path.upper():
            return "NTUSER.DAT"
        elif 'SYSTEM' in self.hive_path.upper():
            return "SYSTEM"
        elif 'SOFTWARE' in self.hive_path.upper():
            return "SOFTWARE"
        elif 'SAM' in self.hive_path.upper():
            return "SAM"
        
        return "UNKNOWN"
    
    def _key_exists(self, path):
        """Check if key exists"""
        try:
            self.reg.open(path)
            return True
        except:
            return False
    
    def _safe_open(self, path):
        """Safely open registry key"""
        try:
            return self.reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            return None
    
    def analyze_ntuser(self):
        """Analyze NTUSER.DAT"""
        log("[*] Analyzing NTUSER.DAT...", "CYAN")
        
        # UserAssist
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if key := self._safe_open(path):
            userassist = []
            for guid_key in key.subkeys():
                try:
                    count_key = guid_key.subkey("Count")
                    for value in count_key.values():
                        # ROT13 decode
                        decoded_name = codecs.decode(value.name(), 'rot13')
                        data = value.value()
                        
                        if len(data) >= 16:
                            exec_count = struct.unpack('<I', data[4:8])[0]
                            userassist.append({
                                'program': decoded_name,
                                'execution_count': exec_count
                            })
                except:
                    continue
            
            if userassist:
                self.findings['UserAssist'] = sorted(userassist, key=lambda x: x['execution_count'], reverse=True)[:30]
        
        # RecentDocs
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        if key := self._safe_open(path):
            recent = []
            for subkey in key.subkeys():
                try:
                    for value in subkey.values():
                        if value.name() != 'MRUListEx':
                            decoded = value.value().decode('utf-16-le', errors='ignore').rstrip('\x00')
                            if decoded:
                                recent.append(decoded)
                except:
                    continue
            
            if recent:
                self.findings['RecentDocs'] = list(set(recent))[:30]
        
        # TypedPaths (Explorer address bar)
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        if key := self._safe_open(path):
            typed = []
            for value in key.values():
                try:
                    typed.append(value.value())
                except:
                    pass
            
            if typed:
                self.findings['TypedPaths'] = typed
        
        # RunMRU
        path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if key := self._safe_open(path):
            run_mru = []
            for value in key.values():
                if value.name() != 'MRUList':
                    try:
                        run_mru.append(value.value())
                    except:
                        pass
            
            if run_mru:
                self.findings['RunMRU'] = run_mru
    
    def analyze_system(self):
        """Analyze SYSTEM hive"""
        log("[*] Analyzing SYSTEM hive...", "CYAN")
        
        # Current ControlSet
        if select_key := self._safe_open("Select"):
            try:
                current = select_key.value("Current").value()
                self.findings['CurrentControlSet'] = f"ControlSet{current:03d}"
            except:
                pass
        
        # USB Devices
        path = r"ControlSet001\Enum\USBSTOR"
        if key := self._safe_open(path):
            usb_devices = []
            for subkey in key.subkeys():
                try:
                    for device_key in subkey.subkeys():
                        friendly_name = ""
                        serial = device_key.name()
                        
                        try:
                            friendly_name = device_key.value("FriendlyName").value()
                        except:
                            friendly_name = subkey.name()
                        
                        usb_devices.append({
                            'device': friendly_name,
                            'serial': serial,
                            'timestamp': device_key.timestamp()
                        })
                except:
                    continue
            
            if usb_devices:
                self.findings['USB_Devices'] = usb_devices
        
        # Computer Name
        path = r"ControlSet001\Control\ComputerName\ComputerName"
        if key := self._safe_open(path):
            try:
                self.findings['ComputerName'] = key.value("ComputerName").value()
            except:
                pass
        
        # TimeZone
        path = r"ControlSet001\Control\TimeZoneInformation"
        if key := self._safe_open(path):
            try:
                self.findings['TimeZone'] = key.value("TimeZoneKeyName").value()
            except:
                pass
    
    def analyze_software(self):
        """Analyze SOFTWARE hive"""
        log("[*] Analyzing SOFTWARE hive...", "CYAN")
        
        # OS Version
        path = r"Microsoft\Windows NT\CurrentVersion"
        if key := self._safe_open(path):
            os_info = {}
            for val_name in ['ProductName', 'RegisteredOwner', 'CurrentVersion', 'CurrentBuild']:
                try:
                    os_info[val_name] = key.value(val_name).value()
                except:
                    pass
            
            if os_info:
                self.findings['OS_Info'] = os_info
        
        # Network Profiles (WiFi history)
        path = r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        if key := self._safe_open(path):
            networks = []
            for profile_key in key.subkeys():
                try:
                    network = {
                        'name': profile_key.value("ProfileName").value(),
                        'category': profile_key.value("Category").value(),
                    }
                    networks.append(network)
                except:
                    pass
            
            if networks:
                self.findings['Network_Profiles'] = networks
    
    def analyze_sam(self):
        """Analyze SAM hive (user accounts)"""
        log("[*] Analyzing SAM hive...", "CYAN")
        
        path = r"SAM\Domains\Account\Users\Names"
        if key := self._safe_open(path):
            users = []
            for user_key in key.subkeys():
                users.append(user_key.name())
            
            if users:
                self.findings['User_Accounts'] = users
    
    def build_timeline(self):
        """Build timeline of registry events"""
        events = []
        
        try:
            for key in self.reg.root().subkeys():
                try:
                    events.append({
                        'timestamp': key.timestamp(),
                        'path': key.path(),
                        'action': 'Modified'
                    })
                except:
                    pass
        except:
            pass
        
        return sorted(events, key=lambda x: x['timestamp'])[:50]  # Top 50
    
    def analyze(self):
        """Run complete analysis"""
        log(f"\n[*] Registry Hive: {self.hive_path}", "BOLD")
        log(f"[*] Hive Type: {self.hive_type}\n", "BOLD")
        
        if self.hive_type == "NTUSER.DAT":
            self.analyze_ntuser()
        elif self.hive_type == "SYSTEM":
            self.analyze_system()
        elif self.hive_type == "SOFTWARE":
            self.analyze_software()
        elif self.hive_type == "SAM":
            self.analyze_sam()
        else:
            log("[!] Unknown hive type - attempting all parsers", "YELLOW")
            self.analyze_ntuser()
            self.analyze_system()
            self.analyze_software()
            self.analyze_sam()
        
        return self.findings
    
    def print_findings(self):
        """Print findings in human-readable format"""
        for category, data in self.findings.items():
            log(f"\n[+] {category}:", "GREEN")
            
            if isinstance(data, list):
                for item in data[:20]:  # Limit output
                    if isinstance(item, dict):
                        print(f"    {item}")
                    else:
                        print(f"    - {item}")
                if len(data) > 20:
                    print(f"    ... and {len(data) - 20} more")
            elif isinstance(data, dict):
                for k, v in data.items():
                    print(f"    {k}: {v}")
            else:
                print(f"    {data}")

# === MAIN ===
def main():
    log("\n--- Enhanced Registry Hunter v2.0 ---\n", "BOLD")
    
    if len(sys.argv) < 2:
        log("Usage: ./registry_hunter.py <hive_file> [--json]", "RED")
        print("Example: ./registry_hunter.py NTUSER.DAT")
        sys.exit(1)
    
    hive_path = sys.argv[1]
    json_output = "--json" in sys.argv
    
    if not os.path.exists(hive_path):
        log(f"[-] File not found: {hive_path}", "RED")
        sys.exit(1)
    
    try:
        hunter = RegistryHunter(hive_path)
        findings = hunter.analyze()
        
        if json_output:
            print(json.dumps(findings, indent=2, default=str))
        else:
            hunter.print_findings()
            
            # Timeline
            log("\n[*] Building timeline...", "CYAN")
            timeline = hunter.build_timeline()
            if timeline:
                log("\n[+] Recent Registry Activity (Top 10):", "GREEN")
                for event in timeline[:10]:
                    print(f"    [{event['timestamp']}] {event['path']}")
        
        log("\n[✓] Analysis Complete\n", "BOLD")
    
    except Exception as e:
        log(f"[!] Error: {e}", "RED")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
