#!/usr/bin/env python3

"""
update_db.py - Enhanced Exploit Database Synchronization v2.0

Maintains local exploit-db with NVD enrichment and batch processing
"""

import sqlite3
import subprocess
import os
import sys
import csv
import requests
import time
from collections import deque

# === COLORS ===
C = {
    'G': '\033[92m',
    'Y': '\033[93m',
    'R': '\033[91m',
    'B': '\033[94m',
    'C': '\033[96m',
    'W': '\033[1m',
    'N': '\033[0m',
}

def log(msg, color='B'):
    print(f"{C.get(color, '')}{msg}{C['N']}")

# === DEPENDENCY CHECK ===
def check_dependencies():
    """Comprehensive dependency checking"""
    log("[*] Checking dependencies...", "B")
    
    missing_required = []
    missing_optional = []
    
    # Required Python modules
    try:
        import sqlite3
    except:
        missing_required.append("sqlite3 (python3-sqlite)")
    
    try:
        import requests
    except:
        missing_required.append("requests (python3-requests)")
    
    # Optional tools
    import shutil
    if not shutil.which('git'):
        missing_optional.append("git (git)")
    
    if not shutil.which('searchsploit'):
        missing_optional.append("searchsploit (exploitdb)")
    
    if missing_required:
        log("[✗] MISSING REQUIRED DEPENDENCIES:", "R")
        for dep in missing_required:
            print(f"    {dep}")
        print(f"\n{C['Y']}Install with:{C['N']}")
        print(f"    {C['W']}pip3 install requests{C['N']}\n")
        return False
    
    if missing_optional:
        log("[!] Missing optional tools:", "Y")
        for dep in missing_optional:
            print(f"    {dep}")
        log("(Will use fallback methods)\n", "C")
    else:
        log("[✓] All dependencies satisfied!\n", "G")
    
    return True

if not check_dependencies():
    sys.exit(1)

# === RATE LIMITER ===
class RateLimiter:
    """Smart rate limiter for API calls"""
    
    def __init__(self, max_calls, period):
        self.calls = deque()
        self.max_calls = max_calls
        self.period = period
    
    def wait_if_needed(self):
        """Enforce rate limiting"""
        now = time.time()
        
        # Remove old calls outside window
        while self.calls and self.calls[0] < now - self.period:
            self.calls.popleft()
        
        # Check if we're at limit
        if len(self.calls) >= self.max_calls:
            sleep_time = self.period - (now - self.calls[0])
            if sleep_time > 0:
                log(f"[*] Rate limit - waiting {sleep_time:.1f}s...", "Y")
                time.sleep(sleep_time)
                # Recursive call to recheck
                return self.wait_if_needed()
        
        self.calls.append(now)

# === DATABASE ===
DB_PATH = os.path.join(os.path.dirname(__file__), 'exploits.db')

def init_database():
    """Initialize database with schema"""
    log("[*] Initializing database...", "B")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table with indexes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exploits (
            edb_id INTEGER PRIMARY KEY,
            cve_id TEXT,
            title TEXT,
            description TEXT,
            type TEXT,
            platform TEXT,
            author TEXT,
            date TEXT,
            file TEXT,
            verified INTEGER DEFAULT 0,
            cvss_score REAL,
            severity TEXT,
            version TEXT
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss ON exploits(cvss_score DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON exploits(type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve ON exploits(cve_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_title ON exploits(title)')
    
    conn.commit()
    conn.close()
    
    log("[✓] Database initialized", "G")

# === EXPLOIT-DB SYNC ===
def sync_exploitdb():
    """Sync exploit-db repository"""
    log("\n[*] Syncing Exploit-DB...", "B")
    
    import shutil
    exploit_dir = os.path.expanduser('~/.exploitdb')
    
    if shutil.which('git'):
        if os.path.exists(exploit_dir):
            log("[*] Updating existing repository...", "C")
            try:
                subprocess.run(['git', '-C', exploit_dir, 'pull'], 
                             capture_output=True, timeout=300)
                log("[✓] Repository updated", "G")
            except:
                log("[!] Git pull failed", "Y")
                return False
        else:
            log("[*] Cloning repository (this may take a while)...", "C")
            try:
                subprocess.run(['git', 'clone', '--depth', '1',
                              'https://gitlab.com/exploit-database/exploitdb.git',
                              exploit_dir],
                             capture_output=True, timeout=600)
                log("[✓] Repository cloned", "G")
            except:
                log("[!] Git clone failed", "R")
                return False
        
        # Get CSV path
        csv_path = os.path.join(exploit_dir, 'files_exploits.csv')
        if os.path.exists(csv_path):
            return csv_path
    
    # Fallback: look for local CSV
    local_csv = os.path.join(os.path.dirname(__file__), 'files_exploits.csv')
    if os.path.exists(local_csv):
        log("[*] Using local CSV file", "Y")
        return local_csv
    
    log("[!] No exploit database found", "R")
    return None

# === NVD ENRICHMENT ===
def enrich_with_nvd(cve_id, rate_limiter):
    """Enrich exploit with NVD data"""
    if not cve_id or not cve_id.startswith('CVE-'):
        return None, None
    
    rate_limiter.wait_if_needed()
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        resp = requests.get(url, timeout=15)
        
        if resp.status_code == 200:
            data = resp.json()
            
            # Extract CVSS score
            if 'result' in data and 'CVE_Items' in data['result']:
                item = data['result']['CVE_Items'][0]
                
                # Try CVSS v3
                if 'impact' in item:
                    if 'baseMetricV3' in item['impact']:
                        cvss = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                        severity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        return cvss, severity
                    elif 'baseMetricV2' in item['impact']:
                        cvss = item['impact']['baseMetricV2']['cvssV2']['baseScore']
                        severity = item['impact']['baseMetricV2']['severity']
                        return cvss, severity
    except:
        pass
    
    return None, None

# === IMPORT EXPLOITS ===
def import_exploits(csv_path):
    """Import exploits from CSV with batch processing"""
    if not csv_path:
        return
    
    log(f"\n[*] Importing exploits from CSV...", "B")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get last imported ID for differential sync
    cursor.execute("SELECT MAX(edb_id) FROM exploits")
    last_id = cursor.fetchone()[0] or 0
    
    rate_limiter = RateLimiter(max_calls=50, period=30)  # 50 requests per 30 seconds
    
    batch = []
    batch_size = 1000
    processed = 0
    enriched = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                edb_id = int(row.get('id', 0))
                
                # Skip if already imported (differential sync)
                if edb_id <= last_id:
                    continue
                
                cve_id = row.get('codes', '')
                title = row.get('description', '')
                exp_type = row.get('type', '')
                platform = row.get('platform', '')
                author = row.get('author', '')
                date = row.get('date', '')
                file_path = row.get('file', '')
                
                # Check if file exists (verified)
                verified = 1 if file_path and os.path.exists(file_path) else 0
                
                # NVD enrichment (every 10th exploit to save time)
                cvss, severity = None, None
                if cve_id and processed % 10 == 0:
                    cvss, severity = enrich_with_nvd(cve_id, rate_limiter)
                    if cvss:
                        enriched += 1
                
                batch.append((
                    edb_id, cve_id, title, '', exp_type, platform, author, date,
                    file_path, verified, cvss, severity, ''
                ))
                
                # Batch insert
                if len(batch) >= batch_size:
                    cursor.executemany('''
                        INSERT OR REPLACE INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ''', batch)
                    conn.commit()
                    processed += len(batch)
                    log(f"    Processed: {processed} exploits ({enriched} enriched)", "C")
                    batch = []
        
        # Final batch
        if batch:
            cursor.executemany('''
                INSERT OR REPLACE INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', batch)
            conn.commit()
            processed += len(batch)
        
        log(f"\n[✓] Imported {processed} exploits ({enriched} with NVD data)", "G")
    
    except Exception as e:
        log(f"[!] Import error: {e}", "R")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

# === MAIN ===
def main():
    log("\n--- Enhanced Exploit Database Updater v2.0 ---\n", "W")
    
    # Initialize database
    init_database()
    
    # Sync exploit-db
    csv_path = sync_exploitdb()
    
    if not csv_path:
        log("[!] No exploit data source available", "R")
        sys.exit(1)
    
    # Import exploits
    import_exploits(csv_path)
    
    # Show stats
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM exploits")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE cvss_score IS NOT NULL")
    with_cvss = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE verified = 1")
    verified = cursor.fetchone()[0]
    
    conn.close()
    
    log(f"\n[*] Database Statistics:", "W")
    print(f"    Total exploits: {total}")
    print(f"    With CVSS data: {with_cvss}")
    print(f"    Verified PoCs: {verified}")
    
    log(f"\n[✓] Database updated: {DB_PATH}\n", "G")

if __name__ == "__main__":
    main()
