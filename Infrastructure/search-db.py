#!/usr/bin/env python3

"""
Search-DB.py - Enhanced Exploit Database Search v3.0

Smart exploit searching with lethality scoring, version filtering,
FTS support, platform/type filters, and CSV export.
"""

import sqlite3
import os
import sys
import re
import csv as csv_module
from datetime import datetime

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


# === DEPENDENCY CHECK ===
def check_dependencies():
    """Check for required Python modules"""
    log("[*] Checking dependencies...", "B")

    missing = []

    try:
        import sqlite3 as _  # noqa: F811
    except ImportError:
        missing.append("sqlite3 (python3-sqlite)")

    if missing:
        log("[✗] MISSING DEPENDENCIES:", "R")
        for dep in missing:
            print(f"    {dep}")
        return False

    log("[✓] All dependencies satisfied!\n", "G")
    return True


if not check_dependencies():
    sys.exit(1)


# === SHOW HELP ===
def show_help():
    log(f"\n--- Enhanced Exploit Database Search v{VERSION} ---\n", "W")
    log("Usage: ./Search-DB.py <keyword|CVE-ID> [options]\n", "R")
    print("Options:")
    print("  --version=X.X       Filter by target version")
    print("  --verified          Only show verified exploits")
    print("  --type=TYPE         Filter by type (remote/local/dos/webapps)")
    print("  --platform=PLAT     Filter by platform (linux/windows/etc)")
    print("  --limit=N           Limit results (default: 20)")
    print("  --export-csv=FILE   Export results to CSV file")
    print("  --offline           Skip online CVE lookups")
    print("  -h, --help          Show this help")
    print("  -v, --version-info  Show version")
    print("\nExamples:")
    print("  ./Search-DB.py apache")
    print("  ./Search-DB.py CVE-2021-44228")
    print("  ./Search-DB.py wordpress --version=5.8 --verified")
    print("  ./Search-DB.py ssh --type=remote --platform=linux --limit=50")
    print("  ./Search-DB.py apache --export-csv=results.csv\n")
    sys.exit(0)


# === DATABASE PATH ===
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exploits.db')


# === CVE LOOKUP (offline-first) ===
def lookup_cve_offline(cve_id):
    """Search the local database for CVE references"""
    if not os.path.exists(DB_PATH):
        return []

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT edb_id FROM exploits WHERE cve_id LIKE ?", (f'%{cve_id}%',))
        rows = cursor.fetchall()
        conn.close()
        return [row['edb_id'] for row in rows]
    except Exception:
        return []


def lookup_cve_online(cve_id):
    """Look up CVE online to find EDB IDs"""
    # Validate CVE format strictly
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        log(f"[!] Invalid CVE format: {cve_id} (expected CVE-YYYY-NNNNN)", "Y")
        return []

    log(f"[*] Looking up {cve_id} online...", "C")

    try:
        import requests
    except ImportError:
        log("[!] 'requests' not installed — skipping online lookup", "Y")
        log("    Install with: pip3 install requests", "C")
        return []

    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(url, timeout=15)

        if resp.status_code == 200:
            data = resp.json()

            # Extract Exploit-DB references
            edb_ids = []
            if 'references' in data:
                for ref in data['references']:
                    if 'exploit-db.com' in ref:
                        if match := re.search(r'/exploits/(\d+)', ref):
                            edb_ids.append(int(match.group(1)))

            if edb_ids:
                log(f"[+] Found EDB IDs: {edb_ids}", "G")
                return edb_ids
            else:
                log(f"[!] No Exploit-DB entries found for {cve_id}", "Y")
        elif resp.status_code == 404:
            log(f"[!] CVE {cve_id} not found in database", "Y")
        else:
            log(f"[!] CVE lookup failed (HTTP {resp.status_code})", "R")
    except requests.exceptions.Timeout:
        log("[!] CVE lookup timed out", "Y")
    except requests.exceptions.ConnectionError:
        log("[!] CVE lookup failed — no network connection", "Y")
    except Exception as e:
        log(f"[!] CVE lookup error: {e}", "R")

    return []


# === LETHALITY SCORING ===
def calculate_lethality(exploit):
    """Calculate exploit lethality score"""
    score = 0
    title = exploit.get('title', '').lower()
    exp_type = exploit.get('type', '').lower()
    file_path = exploit.get('file', '')

    # Type weighting
    type_scores = {
        'remote': 50,
        'webapps': 40,
        'local': 30,
        'dos': 10,
    }
    score += type_scores.get(exp_type, 0)

    # Keyword weighting
    keywords = {
        'rce': 100,
        'remote code execution': 100,
        'buffer overflow': 80,
        'arbitrary code': 90,
        'command injection': 85,
        'sql injection': 70,
        'authentication bypass': 60,
        'privilege escalation': 75,
        'arbitrary file': 65,
        'path traversal': 55,
        'directory traversal': 55,
        'file inclusion': 60,
        'deserialization': 75,
        'xxe': 55,
        'ssrf': 50,
        'denial of service': 15,
    }

    for keyword, points in keywords.items():
        if keyword in title:
            score += points

    # File extension bonus (indicates working PoC)
    ext_scores = {
        '.rb': 25,    # Metasploit
        '.py': 15,    # Python exploit
        '.c': 10,     # C exploit
        '.sh': 5,     # Shell script
        '.pl': 5,     # Perl
        '.go': 10,    # Go exploit
    }

    for ext, points in ext_scores.items():
        if file_path and file_path.endswith(ext):
            score += points

    # CVSS score bonus
    cvss = exploit.get('cvss_score')
    if cvss is not None:
        try:
            score += float(cvss) * 10
        except (ValueError, TypeError):
            pass

    # Verified exploit bonus
    if exploit.get('verified'):
        score += 20

    return score


# === VERSION FILTERING ===
def parse_version_tuple(ver_str):
    """Parse version string into comparable tuple"""
    try:
        return tuple(int(x) for x in re.findall(r'\d+', ver_str))
    except (ValueError, AttributeError):
        return ()


def version_matches(target_version, exploit_version):
    """Check if version matches exploit range"""
    if not target_version or not exploit_version:
        return True  # No filter

    target_parts = parse_version_tuple(target_version)
    if not target_parts:
        return True

    try:
        # Handle ranges like "< 2.4.50"
        if '<=' in exploit_version:
            max_ver = exploit_version.split('<=')[1].strip()
            return target_parts <= parse_version_tuple(max_ver)
        elif '<' in exploit_version:
            max_ver = exploit_version.split('<')[1].strip()
            return target_parts < parse_version_tuple(max_ver)
        elif '>=' in exploit_version:
            min_ver = exploit_version.split('>=')[1].strip()
            return target_parts >= parse_version_tuple(min_ver)
        elif '>' in exploit_version:
            min_ver = exploit_version.split('>')[1].strip()
            return target_parts > parse_version_tuple(min_ver)
        elif target_version in exploit_version:
            return True
    except (ValueError, IndexError):
        pass

    return False


# === SEARCH ===
def search_exploits(keyword=None, cve_id=None, version=None,
                    verified_only=False, type_filter=None,
                    platform_filter=None, offline=False, limit=20):
    """Search exploit database"""
    if not os.path.exists(DB_PATH):
        log(f"[!] Database not found: {DB_PATH}", "R")
        log("    Run Update-DB.py first!", "Y")
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    results = []

    if cve_id:
        # Offline search first
        edb_ids = lookup_cve_offline(cve_id)

        # Online search if no local results and not offline mode
        if not edb_ids and not offline:
            edb_ids = lookup_cve_online(cve_id)

        if edb_ids:
            placeholders = ','.join('?' * len(edb_ids))
            cursor.execute(f"SELECT * FROM exploits WHERE edb_id IN ({placeholders})", edb_ids)
            results = cursor.fetchall()
        else:
            # Fallback: search CVE column in local DB
            cursor.execute("SELECT * FROM exploits WHERE cve_id LIKE ?", (f'%{cve_id}%',))
            results = cursor.fetchall()

    elif keyword:
        # Sanitize keyword length
        keyword = keyword[:200]

        # Keyword search
        query = "SELECT * FROM exploits WHERE title LIKE ? OR description LIKE ?"
        params = [f'%{keyword}%', f'%{keyword}%']

        if type_filter:
            query += " AND type = ?"
            params.append(type_filter)

        if platform_filter:
            query += " AND platform LIKE ?"
            params.append(f'%{platform_filter}%')

        cursor.execute(query, params)
        results = cursor.fetchall()

    conn.close()

    # Convert to dicts & filter
    exploits = []
    for row in results:
        exploit = dict(row)

        # Version filtering
        if version and not version_matches(version, exploit.get('version', '')):
            continue

        # Verified-only filter
        if verified_only and not exploit.get('verified'):
            continue

        # Calculate score
        exploit['lethality'] = calculate_lethality(exploit)
        exploits.append(exploit)

    # Sort by lethality
    exploits.sort(key=lambda x: x['lethality'], reverse=True)

    return exploits[:limit * 5]  # Over-fetch then display limit


# === DISPLAY ===
def display_exploits(exploits, limit=20):
    """Display exploit results"""
    if not exploits:
        log("[!] No exploits found", "Y")
        return

    total = len(exploits)
    show = min(total, limit)
    log(f"\n[+] Found {total} exploits (showing top {show}):\n", "G")

    for i, exp in enumerate(exploits[:limit], 1):
        score = exp['lethality']
        edb_id = exp.get('edb_id', 'N/A')
        title = exp.get('title', 'Unknown')
        exp_type = exp.get('type', 'unknown')
        platform = exp.get('platform', '?')
        cvss = exp.get('cvss_score', 'N/A')

        # Color based on score
        if score >= 200:
            color = 'R'  # Critical
        elif score >= 100:
            color = 'Y'  # High
        else:
            color = 'C'  # Medium

        print(f"{C[color]}{i:2d}. [EDB-{edb_id}] {title[:90]}{C['N']}")
        print(f"    Type: {exp_type} | Platform: {platform} | Lethality: {score} | CVSS: {cvss}")

        if file_path := exp.get('file'):
            print(f"    File: {file_path}")

        print()


# === CSV EXPORT ===
def export_csv(exploits, filepath):
    """Export results to CSV"""
    if not exploits:
        log("[!] No results to export", "Y")
        return

    try:
        fieldnames = ['edb_id', 'cve_id', 'title', 'type', 'platform',
                      'author', 'date', 'cvss_score', 'lethality', 'file']
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv_module.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for exp in exploits:
                writer.writerow(exp)
        log(f"[✓] Exported {len(exploits)} results to {filepath}", "G")
    except PermissionError:
        log(f"[!] Permission denied writing to: {filepath}", "R")
    except Exception as e:
        log(f"[!] Export error: {e}", "R")


# === MAIN ===
def main():
    log(f"\n--- Enhanced Exploit Database Search v{VERSION} ---\n", "W")

    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        show_help()

    if sys.argv[1] in ('-v', '--version-info'):
        print(f"Search-DB v{VERSION}")
        sys.exit(0)

    query = sys.argv[1]
    version = None
    verified_only = False
    type_filter = None
    platform_filter = None
    limit = 20
    export_file = None
    offline = False

    # Parse options
    for arg in sys.argv[2:]:
        if arg.startswith('--version='):
            version = arg.split('=', 1)[1]
        elif arg == '--verified':
            verified_only = True
        elif arg.startswith('--type='):
            type_filter = arg.split('=', 1)[1]
        elif arg.startswith('--platform='):
            platform_filter = arg.split('=', 1)[1]
        elif arg.startswith('--limit='):
            try:
                limit = max(1, min(500, int(arg.split('=', 1)[1])))
            except ValueError:
                log("[!] Invalid --limit value, using default 20", "Y")
        elif arg.startswith('--export-csv='):
            export_file = arg.split('=', 1)[1]
        elif arg == '--offline':
            offline = True
        elif arg in ('-h', '--help'):
            show_help()
        else:
            log(f"[!] Unknown option: {arg}", "Y")

    # Determine query type
    if query.upper().startswith('CVE-'):
        exploits = search_exploits(
            cve_id=query.upper(), version=version,
            verified_only=verified_only, offline=offline, limit=limit
        )
    else:
        exploits = search_exploits(
            keyword=query, version=version, verified_only=verified_only,
            type_filter=type_filter, platform_filter=platform_filter,
            offline=offline, limit=limit
        )

    display_exploits(exploits, limit=limit)

    if export_file:
        export_csv(exploits, export_file)

    log("[✓] Search complete\n", "G")


if __name__ == "__main__":
    main()
