#!/usr/bin/env python3

"""
Update-DB.py - Enhanced Exploit Database Synchronization v3.0

Maintains local exploit-db with NVD enrichment, batch processing,
WAL mode, progress bars, and NVD API v2 support.
"""

import sqlite3
import subprocess
import os
import sys
import csv
import time
import shutil
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

VERSION = "3.0"

def log(msg, color='B'):
    print(f"{C.get(color, '')}{msg}{C['N']}")


# === PROGRESS BAR ===
def progress_bar(current, total, task="Processing", width=40):
    if total <= 0:
        return
    percent = int((current / total) * 100)
    filled = int((current / total) * width)
    bar = '█' * filled + '░' * (width - filled)
    print(f"\r{C['C']}[{bar}] {percent}% — {task} ({current}/{total}){C['N']}", end='', flush=True)
    if current >= total:
        print()


# === DEPENDENCY CHECK ===
def check_dependencies():
    """Comprehensive dependency checking"""
    log("[*] Checking dependencies...", "B")

    missing_required = []
    missing_optional = []

    # Required Python modules
    try:
        import sqlite3 as _  # noqa: F811
    except ImportError:
        missing_required.append("sqlite3 (python3-sqlite)")

    # Optional modules
    try:
        import requests as _  # noqa: F811
    except ImportError:
        missing_optional.append("requests (pip3 install requests)")

    # Optional tools
    if not shutil.which('git'):
        missing_optional.append("git (apt install git)")

    if not shutil.which('searchsploit'):
        missing_optional.append("searchsploit (apt install exploitdb)")

    if missing_required:
        log("[✗] MISSING REQUIRED DEPENDENCIES:", "R")
        for dep in missing_required:
            print(f"    {dep}")
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


# === SHOW HELP ===
def show_help():
    log(f"\n--- Enhanced Exploit Database Updater v{VERSION} ---\n", "W")
    log("Usage: ./Update-DB.py [options]\n", "R")
    print("Options:")
    print("  --force          Re-import all exploits (bypass differential sync)")
    print("  --stats-only     Only show database statistics")
    print("  --no-enrich      Skip NVD enrichment")
    print("  --enrich-all     Enrich all CVEs (slow, respects rate limits)")
    print("  -h, --help       Show this help")
    print("  -v, --version    Show version\n")
    sys.exit(0)


# === RATE LIMITER ===
class RateLimiter:
    """Smart rate limiter for API calls"""

    def __init__(self, max_calls, period):
        self.calls = deque()
        self.max_calls = max_calls
        self.period = period
        self._depth = 0  # Prevent infinite recursion

    def wait_if_needed(self):
        """Enforce rate limiting"""
        now = time.monotonic()  # Use monotonic to prevent time manipulation

        # Remove old calls outside window
        while self.calls and self.calls[0] < now - self.period:
            self.calls.popleft()

        # Check if we're at limit
        if len(self.calls) >= self.max_calls:
            sleep_time = self.period - (now - self.calls[0])
            if sleep_time > 0:
                sleep_time = min(sleep_time, self.period)  # Cap sleep time
                log(f"[*] Rate limit — waiting {sleep_time:.1f}s...", "Y")
                time.sleep(sleep_time)

                # Clear stale entries after sleeping
                now = time.monotonic()
                while self.calls and self.calls[0] < now - self.period:
                    self.calls.popleft()

        self.calls.append(time.monotonic())


# === DATABASE ===
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exploits.db')


def init_database():
    """Initialize database with schema and WAL mode"""
    log("[*] Initializing database...", "B")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Enable WAL mode for better concurrency
    cursor.execute("PRAGMA journal_mode=WAL")

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
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_platform ON exploits(platform)')

    # Create FTS virtual table for fast text search
    try:
        cursor.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5(
                title, description,
                content='exploits',
                content_rowid='edb_id'
            )
        ''')
    except sqlite3.OperationalError:
        # FTS5 may not be available in all SQLite builds
        pass

    conn.commit()
    conn.close()

    log("[✓] Database initialized", "G")


# === EXPLOIT-DB SYNC ===
EXPECTED_REMOTE_URL = "https://gitlab.com/exploit-database/exploitdb.git"


def sync_exploitdb():
    """Sync exploit-db repository"""
    log("\n[*] Syncing Exploit-DB...", "B")

    exploit_dir = os.path.expanduser('~/.exploitdb')

    if shutil.which('git'):
        if os.path.exists(exploit_dir):
            # Validate the remote URL before pulling
            try:
                result = subprocess.run(
                    ['git', '-C', exploit_dir, 'remote', 'get-url', 'origin'],
                    capture_output=True, text=True, timeout=10
                )
                actual_url = result.stdout.strip()
                if EXPECTED_REMOTE_URL not in actual_url:
                    log(f"[!] Unexpected git remote: {actual_url}", "Y")
                    log(f"    Expected: {EXPECTED_REMOTE_URL}", "C")
                    log("    Skipping pull for safety", "Y")
                    return None
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                pass

            log("[*] Updating existing repository...", "C")
            try:
                subprocess.run(
                    ['git', '-C', exploit_dir, 'pull', '--ff-only'],
                    capture_output=True, timeout=300
                )
                log("[✓] Repository updated", "G")
            except subprocess.TimeoutExpired:
                log("[!] Git pull timed out (300s)", "Y")
                return None
            except subprocess.SubprocessError:
                log("[!] Git pull failed", "Y")
                return None
        else:
            log("[*] Cloning repository (this may take a while)...", "C")
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1',
                     EXPECTED_REMOTE_URL, exploit_dir],
                    capture_output=True, timeout=600
                )
                log("[✓] Repository cloned", "G")
            except subprocess.TimeoutExpired:
                log("[!] Git clone timed out (600s)", "R")
                return None
            except subprocess.SubprocessError:
                log("[!] Git clone failed", "R")
                return None

        # Get CSV path
        csv_path = os.path.join(exploit_dir, 'files_exploits.csv')
        if os.path.exists(csv_path):
            return csv_path

    # Fallback: look for local CSV
    local_csv = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files_exploits.csv')
    if os.path.exists(local_csv):
        log("[*] Using local CSV file", "Y")
        return local_csv

    log("[!] No exploit database found", "R")
    return None


# === NVD ENRICHMENT (v2 API) ===
def enrich_with_nvd(cve_id, rate_limiter):
    """Enrich exploit with NVD data (supports v2 API)"""
    if not cve_id or not cve_id.startswith('CVE-'):
        return None, None

    try:
        import requests
    except ImportError:
        return None, None

    rate_limiter.wait_if_needed()

    try:
        # Try NVD API v2 first
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = requests.get(url, timeout=20, headers={
            'User-Agent': 'AntiGravity-UpdateDB/3.0'
        })

        if resp.status_code == 200:
            data = resp.json()

            if 'vulnerabilities' in data and data['vulnerabilities']:
                vuln = data['vulnerabilities'][0].get('cve', {})
                metrics = vuln.get('metrics', {})

                # Try CVSS v3.1 first, then v3.0, then v2
                for version_key in ['cvssMetricV31', 'cvssMetricV30']:
                    if version_key in metrics:
                        metric = metrics[version_key][0]
                        cvss_data = metric.get('cvssData', {})
                        score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity')
                        if score:
                            return score, severity

                if 'cvssMetricV2' in metrics:
                    metric = metrics['cvssMetricV2'][0]
                    cvss_data = metric.get('cvssData', {})
                    score = cvss_data.get('baseScore')
                    severity = metric.get('baseSeverity')
                    if score:
                        return score, severity

        elif resp.status_code == 403:
            # Rate limited — back off
            time.sleep(5)
        elif resp.status_code != 404:
            pass  # Silently skip other errors

    except Exception:
        pass

    return None, None


# === IMPORT EXPLOITS ===
def import_exploits(csv_path, force=False, enrich=True, enrich_all=False):
    """Import exploits from CSV with batch processing and progress"""
    if not csv_path:
        return

    log(f"\n[*] Importing exploits from CSV...", "B")

    # Count total lines first for progress bar
    total_lines = 0
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f) - 1  # Subtract header
        log(f"    Total entries in CSV: {total_lines}", "C")
    except Exception:
        total_lines = 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get last imported ID for differential sync
    last_id = 0
    if not force:
        cursor.execute("SELECT MAX(edb_id) FROM exploits")
        result = cursor.fetchone()
        last_id = result[0] if result and result[0] else 0
        if last_id > 0:
            log(f"    Differential sync from EDB-{last_id}", "C")

    rate_limiter = RateLimiter(max_calls=45, period=30)  # Stay under limits

    batch = []
    batch_size = 1000
    processed = 0
    imported = 0
    enriched = 0

    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)

            for row in reader:
                processed += 1

                if total_lines > 0 and processed % 5000 == 0:
                    progress_bar(processed, total_lines, "Reading CSV")

                try:
                    edb_id = int(row.get('id', 0))
                except (ValueError, TypeError):
                    continue

                # Skip if already imported (differential sync)
                if not force and edb_id <= last_id:
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

                # NVD enrichment
                cvss, severity = None, None
                if enrich and cve_id:
                    # Enrich every 10th exploit by default, or all if --enrich-all
                    if enrich_all or imported % 10 == 0:
                        cvss, severity = enrich_with_nvd(cve_id, rate_limiter)
                        if cvss:
                            enriched += 1

                batch.append((
                    edb_id, cve_id, title, '', exp_type, platform, author, date,
                    file_path, verified, cvss, severity, ''
                ))
                imported += 1

                # Batch insert with transaction
                if len(batch) >= batch_size:
                    try:
                        cursor.execute("BEGIN TRANSACTION")
                        cursor.executemany('''
                            INSERT OR REPLACE INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ''', batch)
                        cursor.execute("COMMIT")
                    except sqlite3.Error as e:
                        cursor.execute("ROLLBACK")
                        log(f"\n[!] Batch insert error: {e}", "R")
                    batch = []

        # Final batch
        if batch:
            try:
                cursor.execute("BEGIN TRANSACTION")
                cursor.executemany('''
                    INSERT OR REPLACE INTO exploits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', batch)
                cursor.execute("COMMIT")
            except sqlite3.Error as e:
                cursor.execute("ROLLBACK")
                log(f"\n[!] Final batch error: {e}", "R")

        # Update FTS index
        try:
            cursor.execute("INSERT INTO exploits_fts(exploits_fts) VALUES('rebuild')")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # FTS not available

        if total_lines > 0:
            progress_bar(total_lines, total_lines, "Import complete")

        log(f"\n[✓] Imported {imported} new exploits ({enriched} with NVD data)", "G")

    except FileNotFoundError:
        log(f"[!] CSV file not found: {csv_path}", "R")
    except PermissionError:
        log(f"[!] Permission denied reading: {csv_path}", "R")
    except Exception as e:
        log(f"[!] Import error: {e}", "R")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()


# === SHOW STATS ===
def show_stats():
    """Show database statistics"""
    if not os.path.exists(DB_PATH):
        log("[!] Database not found. Run update first.", "R")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM exploits")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM exploits WHERE cvss_score IS NOT NULL")
    with_cvss = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM exploits WHERE verified = 1")
    verified = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT type) FROM exploits")
    type_count = cursor.fetchone()[0]

    cursor.execute("SELECT type, COUNT(*) FROM exploits GROUP BY type ORDER BY COUNT(*) DESC")
    type_breakdown = cursor.fetchall()

    cursor.execute("SELECT COUNT(DISTINCT platform) FROM exploits")
    platform_count = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(cvss_score) FROM exploits WHERE cvss_score IS NOT NULL")
    avg_cvss_row = cursor.fetchone()
    avg_cvss = f"{avg_cvss_row[0]:.1f}" if avg_cvss_row[0] else "N/A"

    # DB file size
    db_size = os.path.getsize(DB_PATH)
    db_size_human = f"{db_size / (1024*1024):.1f} MB"

    conn.close()

    log(f"\n[*] Database Statistics:", "W")
    print(f"    Database:       {DB_PATH}")
    print(f"    Size:           {db_size_human}")
    print(f"    Total exploits: {total}")
    print(f"    With CVSS data: {with_cvss}")
    print(f"    Verified PoCs:  {verified}")
    print(f"    Avg CVSS:       {avg_cvss}")
    print(f"    Types:          {type_count}")
    print(f"    Platforms:      {platform_count}")

    if type_breakdown:
        print(f"\n    Type breakdown:")
        for t, count in type_breakdown[:6]:
            print(f"      {t or 'unknown':<12} {count}")


# === MAIN ===
def main():
    log(f"\n--- Enhanced Exploit Database Updater v{VERSION} ---\n", "W")

    # Parse arguments
    if '-h' in sys.argv or '--help' in sys.argv:
        show_help()

    if '-v' in sys.argv or '--version' in sys.argv:
        print(f"Update-DB v{VERSION}")
        sys.exit(0)

    force = '--force' in sys.argv
    stats_only = '--stats-only' in sys.argv
    no_enrich = '--no-enrich' in sys.argv
    enrich_all = '--enrich-all' in sys.argv

    if stats_only:
        show_stats()
        sys.exit(0)

    # Initialize database
    init_database()

    # Sync exploit-db
    csv_path = sync_exploitdb()

    if not csv_path:
        log("[!] No exploit data source available", "R")
        log("    Place 'files_exploits.csv' in the script directory, or install git.", "Y")
        sys.exit(1)

    # Import exploits
    import_exploits(csv_path, force=force, enrich=not no_enrich,
                    enrich_all=enrich_all)

    # Show stats
    show_stats()

    log(f"\n[✓] Database updated: {DB_PATH}\n", "G")


if __name__ == "__main__":
    main()
