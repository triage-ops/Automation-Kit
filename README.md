# 1. Binary-Scout.sh — Binary Triage Automation
**Purpose:** Rapid security analysis of ELF/PE binaries for CTF challenges and security auditing.

# Feature List
*   **Shell Configuration** (Lines 1–23): Uses `set -euo pipefail` for strict error handling and defines ANSI color codes.
*   **Dependency Management** (Lines 26–110):
    *   **Required:** `file`, `strings`, `xxd`. Exits immediately if missing.
    *   **Optional:** `checksec`, `readelf`, `nm`, `ldd`, `getcap`, `objdump`. Warnings only.
*   **Optimization** (Lines 115–134): Caches `file` command output to variables `FILE_TYPE` and `FILE_TYPE_MIME` to avoid redundant subprocess calls.
*   **Parallel Execution** (Lines 137–174): Launches tools (`checksec`, `nm`, `readelf`, `ldd`) in background processes to `/tmp/binscout_$$`. Uses `wait` to synchronize.
*   **Security Protections** (Lines 176–219):
    *   **Primary:** Displays `checksec` output if available.
    *   **Fallback (Manual ELF Checks):**
        *   **NX:** Parses `readelf -l` for `GNU_STACK` (RWE flags = Disabled).
        *   **PIE:** Parses `readelf -h` Type (`EXEC` = No PIE, `DYN` = PIE).
        *   **Canary:** Searches `nm` output for `__stack_chk_fail`.
*   **Packer Detection** (Lines 222–240): Scans for `UPX!` signature using `ripgrep` (fast) or `strings`. Suggests `upx -d` command.
*   **String Preview** (Lines 243–246): Extracts strings >6 chars (`strings -n 6`), shows first 15 lines.
*   **Architecture & Tools** (Lines 249–280): Specific regex for x86-64, ARM, MIPS, PowerPC, RISC-V, SPARC. Recommends:
    *   **ELF:** Ghidra, GDB (gef), radare2.
    *   **PE:** x64dbg, PE-bear.
    *   **Java/Python:** jadx, uncompyle6.
*   **Dynamic Libs** (Lines 283–328):
    *   If `libc.so` is linked, extracts path and queries **GLIBC version**.
    *   **Heap Exploitation Tips:** Suggests techniques based on version (Tcache for ≥2.27, Fastbin for 2.23-2.26).
    *   **Ret2Libc:** Extracts `system()` offset using `readelf -s`.
*   **Crypto Constants** (Lines 331–364): Scans first **64KB** for MD5, AES S-box, SHA-256 constants + library strings (openssl, mbedtls).
*   **Sandbox/Capabilities/Hijacking** (Lines 367–435):
    *   **Seccomp:** Checks for "seccomp" string/symbols.
    *   **Capabilities:** Runs `getcap`. Flags dangerous `CAP_SETUID`, `CAP_DAC_OVERRIDE`, `CAP_NET_RAW`.
    *   **RPATH Hijacking:** Checks `readelf -d` for relative `RPATH`/`RUNPATH`.
---

# 2. Hash-Detector.sh — Hash ID & Online Cracking
**Purpose:** Identifies hash types, detects JWTs/salted hashes, and attempts cracking.

# Feature List
*   **Input Handling** (Lines 93–111): Accepts file path, string arg, or stdin pipe. Trims whitespace via `xargs`.
*   **Caching System** (Lines 130–155): Results cached in `/tmp/hash_detector_cache` keyed by MD5 of input. Valid for **24 hours**.
*   **Online Lookup** (Lines 157–228):
    *   **APIs:** `hashes.com` (primary) and `md5decrypt.net` (MD5 fallback).
    *   **Resiliency:** 3 retries with exponential backoff (1s, 2s, 4s).
    *   **Parsing:** Uses `jq` if available, falls back to `grep`.
*   **JWT Analysis** (Lines 230–265):
    *   Decodes Header/Payload (URL-safe Base64).
    *   **Vulnerability:** Flags `"alg": "none"`.
    *   **CTF Flags:** Greps payload for `flag{`, `ctf{`, `thm{`, `htb{`.
*   **Salted/Special Hashes** (Lines 267–313):
    *   Detects `hash:salt` format.
    *   Identifies prefix-based hashes: `$2*` (bcrypt), `$argon2*`, `$1$` (MD5-Crypt), `$5$` (SHA256-Crypt), `$6$` (SHA512-Crypt).
*   **Hex Analysis** (Lines 315–387):
    *   Maps length (32, 40, 48, 56, 64, 96, 128) to algorithms (MD5/NTLM, SHA1, SHA256, etc.).
    *   **Hashcat Integration:** Provides specific `hashcat -m <mode>` commands for local cracking.
---

# 3. Header-Fix.sh — File Forensics & Auto-Repair
**Purpose:** Detects corruption, validating headers, calculating entropy, and carving files.

# Feature List
*   **Signature DB** (Lines 97–133): Associative array (`declare -A`) for PNG, JPEG, GIF, BMP, TIFF, WEBP, ZIP, RAR, 7z, GZIP, BZIP2, PDF, Office, ELF, PE, MPEG.
*   **Signature Hunting** (Lines 152–194): Scans first **4KB**. Flags signatures at offset 0 as correct; others as **SHIFTED** (corruption/embedding).
*   **Entropy Analysis** (Lines 196–248): Embedded Python script computes Shannon entropy on first **64KB**.
    *   Score > 7.5: Encrypted/Compressed.
    *   Score < 4.0: Text/Structured.
*   **Deep Validation** (Lines 250–410):
    *   **PNG:** Python script parses chunks (IHDR/IDAT/IEND), validates structure and CRCs.
    *   **JPEG:** Checks SOI (`FF D8`) and EOI (`FF D9`) markers.
    *   **PDF:** Checks `%PDF-` header, `xref` table, and `%%EOF` trailer. Count objects.
    *   **ZIP:** Validates Local Header, Central Directory, and EOCD markers.
*   **Auto-Carving** (Lines 412–439): Uses `dd` to extract files found at shifted offsets. Names file based on detected signature.
*   **Header Repair (The Surgeon)** (Lines 441–522):
    *   If header invalid, determines expected signature from extension.
    *   Creates `.bak` backup.
    *   **Force-Repairs:** Overwrites first N bytes with correct magic bytes.
    *   **PNG-Specific:** Recalculates `IHDR` chunk CRC using Python `binascii.crc32`.
---

# 4. Stego-Hunt.sh — Steganography Suite
**Purpose:** Multi-tool stego analysis for images, audio, and text.

# Feature List
*   **Dependencies** (Lines 28–47): Checks 13 optional tools (`exiftool`, `binwalk`, `steghide`, `zsteg`, `pngcheck`, `sox`, `ffmpeg`, `outguess`, etc.).
*   **Parallel Triage** (Lines 160–177): Runs `exiftool`, `binwalk`, `strings` concurrently in background.
*   **Format-Specific Analysis**:
    *   **PNG:** `pngcheck` (anomalies), `zsteg` (LSB extraction), Python LSB bit-plane extraction (visual `lsb_red.png`, etc.).
    *   **JPEG:** `steghide` (empty password), `stegdetect` (algo detection), `outguess`.
    *   **Audio:** Converts to WAV via `sox`. Generates **spectrograms** (visual hidden cues).
*   **Polyglot Detection** (Lines 353–370): Checks if file is valid as multiple formats (Image+ZIP, Image+PDF).
*   **Whitespace Stego** (Lines 372–395): Runs `stegsnow`. Counts trailing spaces/tabs (>5 lines triggers binary decoding hint).
*   **Barcode/QR** (Lines 334–348): Scans images with `zbarimg` for embedded codes/flags.
*   **Brute Force** (Lines 397–424): Iterates provided wordlist against `steghide` (JPEG only). Shows progress every 1000 attempts.
---

# 5. Ultra_Analyzer.sh — Universal Decoder
**Purpose:** Recursive decoder for 25+ encoding schemes with auto-detection.

# Feature List
*   **Memoization** (Lines 116–137): Caches decoding results (`method:md5(data)`) to prevent loops.
*   **Early Exit** (Lines 139–147): Immediately stops if `flag{`, `ctf{`, etc. is found.
*   **Decoders**:
    *   **Base64:** Validates alphabet + length.
    *   **XOR:** Python brute-forces single-byte XOR (0-255). Heuristic: >85% printable chars AND contains keywords ("flag", "key", "secret").
    *   **Hex:** Validates even length.
    *   **URL:** `%` detection.
    *   **Octal:** Backslash-escaped or space-separated octal.
    *   **HTML Entities:** `&#` or `&lt;` detection.
*   **Recursive Logic** (Lines 242–279): Chains decoders (e.g., Base64 -> URL -> Hex). Depth limit: 5.
*   **Esoteric**:
    *   **Brainfuck:** Embedded Python interpreter (30k cells).
    *   **Hash Detection:** Identifies 32/40/64/128-char hex strings. Auto-cracks with `hashcat` + `rockyou.txt` (30s timeout).
    *   **Crypto Headers:** PGP, OpenSSH, RSA, X.509.
    *   **GPS:** Regex for coordinates -> Google Maps link.
    *   **Freelquency Analysis:** `awk`-based letter frequency count to detect substitution ciphers.
---

#=== Python Scripts ===

# 6. Forensics-Analyzer.py — Forensics Framework
**Purpose:** File and Memory forensics with multi-threading and Volatility support.

# Feature List
*   **Memory Analysis (`MemoryAnalyzer`)**:
    *   **Detection:** Checks extensions (`.vmem`, `.dmp`), magic bytes (`PAGEDUMP`, `\x7fELF...CORE`), size (>50MB).
    *   **Profile:** Auto-detects OS via `banners` (Vol3) or `imageinfo` (Vol2).
    *   **Plugins:** Runs `pslist`, `netscan`, `cmdline`. Adapts syntax for Volatility 2 vs 3.
*   **File Analysis (`ForensicsAgent`)**:
    *   **Hashing:** MD5/SHA1/SHA256. Uses `mmap` for files >100MB.
    *   **Strings:** Regex searches for URLs, Emails, IPs, Paths. Deduplicates results.
    *   **Entropy:** Shannon entropy on first 1MB.
    *   **Stego Checks:** JPEG EOI / PNG IEND trailing data.
    *   **Carving:** Runs `foremost`.
    *   **Threads:** Uses `ThreadPoolExecutor` (4 workers) for parallel Flag Search, String Extraction, EXIF, and Stego checks.
---

# 7. Registry-Hunter.py — Registry Forensics
**Purpose:** Parses Windows Registry Hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT).

# Feature List
*   **Dependency:** `python-registry`.
*   **Hive Identification:** Checks root keys (`SAM\Domains`, `ControlSet001`) or filenames.
*   **NTUSER.DAT:**
    *   **UserAssist:** ROT13 decoding (`codecs.decode`) + Execution count parsing.
    *   **RecentDocs:** UTF-16-LE decoding.
    *   **TypedPaths / RunMRU:** User activity history.
*   **SYSTEM:**
    *   **USBSTOR:** Enumerates connected USBs (Name, Serial, Timestamp).
    *   **CurrentControlSet:** Identifies active set.
    *   **ComputerName / TimeZone**.
*   **SOFTWARE:** OS Version, WiFi Network Profiles.
*   **SAM:** Lists User Accounts.
*   **Timeline:** Extracts modification timestamps from all keys. Sorts top 50 chronological events. Supports `--json`.
---

# 8. Reverse-Engineer.py — Binary Exploitation Helper
**Purpose:** Static analysis, Fuzzing, ROP search, and Exploit template generation.

# Feature List
*   **Analysis:**
    *   **ELF:** Parses header for Arch (x64/x86/ARM) + Bits.
    *   **Symbols:** Extracts dynamic symbols via `nm`.
    *   **Strings:** LRU-cached extraction. checks for 5 flag patterns.
*   **Win Functions:**
    *   Scoring system (10 pts symbol, 5 pts string) for keywords: `win`, `flag`, `backdoor`, `admin`, `pwn`, `system`.
    *   Resolves function addresses.
*   **Fuzzing (`--fuzz` or `--auto`)**:
    *   Generates De Bruijn cyclic pattern (adaptive length: 500-5000).
    *   Pipes to binary (3s timeout).
    *   Monitors `dmesg` for segfaults.
    *   Calculates exact **EIP/RIP offset** from crash address.
*   **Exploitation**:
    *   **ROP:** Searches gadgets (`pop rdi`, `ret`) via `ROPgadget`/`ropper`.
    *   **Template:** Generates `exploit_<name>.py` using `pwntools`. Pre-fills architecture, offset, win function address, and payload skeleton.
---

# 9. Shell-Forger.py — Reverse Shell Generator
**Purpose:** payload generation, HTTP serving, and listening.

# Feature List
*   **Payloads:** Bash (2), Netcat (2), Python (2), PHP, Perl, Ruby, PowerShell, NodeJS, Golang, WebShells (PHP/JSP).
*   **Encodings:** Base64 (with decoding wrapper), URL, Hex, ROT13.
*   **Clipboard:** Auto-copies via `pbcopy` (macOS) or `xclip` (Linux).
*   **HTTP Server (`serve`):** Hosts payload for `curl | bash` injection.
*   **Listener (`listen`):** Raw socket implementation of Netcat. Handles connection + I/O threads.
*   **Obfuscation:** Basic variable randomization support.
---

# 10. search_db.py — Exploit-DB Search
**Purpose:** Local DB search with scoring.

# Feature List
*   **CVE Lookup:** Queries `cve.circl.lu` to find EDB IDs from CVEs.
*   **Lethality Score:**
    *   **Type:** Remote (50) > WebApps (40) > Local (30) > DoS (10).
    *   **Keywords:** RCE (100) > Cmd Inj (85) > Overflow (80) > SQLi (70).
    *   **Extension:** `.rb` (25) > `.py` (15) > `.c` (10) > `.sh` (5).
    *   **Verified:** +20 points.
    *   **CVSS:** Score * 10.
*   **Filters:** `--version` (supports range `< 2.4`), `--verified`.
*   **Output:** Color-coded by lethality (Red/Yellow/Cyan).
---

# 11. update_db.py — DB Sync & Enrich
**Purpose:** Maintains `exploits.db`.

#### 🛠️ Comprehensive Feature List
*   **Rate Limiting:** Sliding window (default 50 calls/30s) for NVD API.
*   **Sync:** `git pull` from `~/.exploitdb` or local CSV fallback.
*   **Import:**
    *   Differential update (checks max `edb_id`).
    *   Batch `INSERT` (1000 rows/batch).
    *   **Enrichment:** Queries NVD API for CVSS scores (every 10th exploit).
*   **Schema:** SQLite table `exploits` with indices on `cvss_score`, `type`, `cve_id`.
---

#=== Supporting Files ===
*   `exploits.db`: Primary SQLite database, updated with CVEs (Optional).
