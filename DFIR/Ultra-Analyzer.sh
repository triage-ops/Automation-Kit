#!/bin/bash

echo '''
8   8                                                                                                                                        
8   8 eeeee eeeee eeee eeeee  eeeee eeeeeee eeeee  e     eeee    eeeee e   e eeee    eeeee eeee eeeee  eeeee eeeeeee eeeee  e     eeee eeeee 
8e  8 8   8 8   " 8  8 8   8  8   8 8  8  8 8   8  8     8         8   8   8 8       8   " 8  8 8   8  8   8 8  8  8 8   8  8     8    8   8 
88  8 8e  8 8eeee 8e   8eee8e 8eee8 8e 8  8 8eee8e 8e    8eee      8e  8eee8 8eee    8eeee 8e   8eee8e 8eee8 8e 8  8 8eee8e 8e    8eee 8e  8 
88  8 88  8    88 88   88   8 88  8 88 8  8 88   8 88    88        88  88  8 88         88 88   88   8 88  8 88 8  8 88   8 88    88   88  8 
88ee8 88  8 8ee88 88e8 88   8 88  8 88 8  8 88eee8 88eee 88ee      88  88  8 88ee    8ee88 88e8 88   8 88  8 88 8  8 88eee8 88eee 88ee 88ee8 
'''
set -uo pipefail

VERSION="3.0"

# --- HELP ---
show_help() {
    echo -e "${BOLD:-}Ultra-Analyzer v${VERSION}${NC:-} \u2014 Universal encoding/cipher detection and decoding"
    echo
    echo "Usage: $0 <string_or_file> [options]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help"
    echo "  -v, --version  Show version"
    echo
    echo "Supported Encodings:"
    echo "  Base64, Base32, Base58, Hex, URL, ROT-N, XOR (single & multi-byte)"
    echo "  Morse, Binary, Octal, HTML entities, Brainfuck, Atbash, Vigenere"
    echo "  Rail Fence, zlib/deflate"
    echo
    echo "Examples:"
    echo "  $0 'SGVsbG8gV29ybGQ='"
    echo "  $0 encoded.txt"
    echo "  echo 'data' | $0"
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        -h|--help)    show_help ;;
        -v|--version) echo "Ultra-Analyzer v${VERSION}"; exit 0 ;;
    esac
done

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- DEPENDENCIES ---
REQUIRED_TOOLS=(
    "base64:coreutils"
    "xxd:xxd"
    "grep:grep"
    "awk:gawk"
    "tr:coreutils"
)

OPTIONAL_TOOLS=(
    "hashcat:hashcat"
    "zbarimg:zbar-tools"
    "python3:python3"
    "perl:perl"
    "bc:bc"
)

# --- DEPENDENCY CHECK ---
check_dependencies() {
    local missing_required=()
    local missing_optional=()

    echo -e "${BLUE}[*] Checking dependencies...${NC}"

    for entry in "${REQUIRED_TOOLS[@]}"; do
        IFS=':' read -r tool package <<< "$entry"
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool ($package)")
        fi
    done

    for entry in "${OPTIONAL_TOOLS[@]}"; do
        IFS=':' read -r tool package <<< "$entry"
        if ! command -v "$tool" &>/dev/null; then
            missing_optional+=("$tool ($package)")
        fi
    done

    if [ ${#missing_required[@]} -gt 0 ]; then
        echo -e "${RED}[✗] MISSING REQUIRED DEPENDENCIES:${NC}"
        printf '%s\n' "${missing_required[@]}" | sed 's/^/    /'
        local packages=()
        for entry in "${REQUIRED_TOOLS[@]}"; do
            IFS=':' read -r tool package <<< "$entry"
            ! command -v "$tool" &>/dev/null && packages+=("$package")
        done
        packages=($(printf '%s\n' "${packages[@]}" | sort -u))
        echo -e "\n${YELLOW}Install with:${NC}"
        echo -e "    ${BOLD}sudo apt install ${packages[*]}${NC}\n"
        exit 1
    fi

    if [ ${#missing_optional[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing optional tools:${NC}"
        printf '%s\n' "${missing_optional[@]}" | sed 's/^/    /'
        echo
    else
        echo -e "${GREEN}[✓] All dependencies satisfied!${NC}\n"
    fi
}

check_dependencies

# --- INPUT HANDLING ---
if [ "$#" -ge 1 ]; then
    if [ -f "$1" ]; then
        INPUT=$(cat "$1")
        IS_FILE=true
    else
        INPUT="$1"
        IS_FILE=false
    fi
else
    if [ ! -t 0 ]; then
        INPUT=$(cat)
        IS_FILE=false
    else
        echo -e "${RED}Usage: $0 <string|file>${NC}"
        exit 1
    fi
fi

# --- WRITE INPUT TO TEMP FILE ONCE (used by all decoders safely) ---
TMP_INPUT=$(mktemp)
echo -n "$INPUT" > "$TMP_INPUT"
trap "rm -f '$TMP_INPUT'" EXIT

# --- FLAG DETECTION ---
check_for_flag() {
    local text="$1"
    if echo "$text" | grep -qiE "(flag|ctf|thm|htb|picoctf|ductf|dice)\{"; then
        FLAG=$(echo "$text" | grep -oE '(flag|FLAG|ctf|CTF|thm|THM|htb|HTB|picoCTF|picoctf|ductf|DUCTF|dice)\{[^}]+\}')
        echo -e "${GREEN}${BOLD}[!!!] FLAG FOUND: $FLAG${NC}"
        rm -f "$TMP_INPUT"
        exit 0
    fi
}

check_for_flag "$INPUT"

# --- MEMOIZATION CACHE ---
declare -A DECODE_CACHE

cached_decode() {
    local method="$1"
    local data="$2"
    local cache_key="${method}:$(echo -n "$data" | md5sum | cut -d' ' -f1)"
    if [ -n "${DECODE_CACHE[$cache_key]:-}" ]; then
        echo "${DECODE_CACHE[$cache_key]}"
        return 0
    fi
    return 1
}

save_decode_cache() {
    local method="$1"
    local data="$2"
    local result="$3"
    local cache_key="${method}:$(echo -n "$data" | md5sum | cut -d' ' -f1)"
    DECODE_CACHE[$cache_key]="$result"
}

# --- BASE64 DECODER ---
decode_base64() {
    local in="$1"
    if cached_result=$(cached_decode "b64" "$in" 2>/dev/null); then
        echo "$cached_result"
        return
    fi
    if [[ "$in" =~ ^[A-Za-z0-9+/=]+$ ]] && [ ${#in} -ge 8 ] && [ $(( ${#in} % 4 )) -eq 0 ]; then
        if decoded=$(echo "$in" | base64 -d 2>/dev/null); then
            # Only return if result looks printable enough
            printable=$(echo "$decoded" | tr -cd '[:print:][:space:]' | wc -c)
            total=${#decoded}
            if [ "$total" -gt 0 ] && [ $(( printable * 100 / total )) -ge 70 ]; then
                save_decode_cache "b64" "$in" "$decoded"
                echo "$decoded"
            fi
        fi
    fi
}

# --- BASE32 DECODER ---
decode_base32() {
    local in="$1"
    # Base32 uses A-Z2-7= characters
    if [[ "$in" =~ ^[A-Z2-7=]+$ ]] && [ ${#in} -ge 8 ] && [ $(( ${#in} % 8 )) -eq 0 ]; then
        if decoded=$(echo "$in" | base32 -d 2>/dev/null); then
            printable=$(echo "$decoded" | tr -cd '[:print:][:space:]' | wc -c)
            total=${#decoded}
            if [ "$total" -gt 0 ] && [ $(( printable * 100 / total )) -ge 70 ]; then
                echo "$decoded"
            fi
        fi
    fi
}

# --- BASE58 DECODER ---
decode_base58() {
    local in="$1"
    # Base58 uses 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz (no 0OIl)
    if [[ "$in" =~ ^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$ ]] && [ ${#in} -ge 10 ]; then
        if command -v python3 &>/dev/null; then
            python3 - "$in" <<'PYEOF'
import sys
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
val = 0
for c in sys.argv[1]:
    val = val * 58 + alphabet.index(c)
hex_str = format(val, 'x')
if len(hex_str) % 2:
    hex_str = '0' + hex_str
try:
    result = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
    printable = sum(32 <= ord(c) <= 126 for c in result)
    if len(result) > 0 and printable / len(result) >= 0.7:
        print(result)
except Exception:
    pass
PYEOF
        fi
    fi
}

# --- BASE64 URL-SAFE DECODER ---
decode_base64url() {
    local in="$1"
    # Convert URL-safe to standard
    local std
    std=$(echo "$in" | tr '_-' '/+')
    case $(( ${#std} % 4 )) in
        2) std="${std}==" ;;
        3) std="${std}=" ;;
    esac
    if decoded=$(echo "$std" | base64 -d 2>/dev/null); then
        echo "$decoded"
    fi
}

# --- HEX DECODER ---
decode_hex() {
    local in="$1"
    # Strip optional 0x prefix and spaces
    local clean
    clean=$(echo "$in" | tr -d '[:space:]' | sed 's/^0x//' | sed 's/\\x//g')
    if [[ "$clean" =~ ^[0-9a-fA-F]+$ ]] && [ $(( ${#clean} % 2 )) -eq 0 ] && [ ${#clean} -ge 4 ]; then
        if decoded=$(echo "$clean" | xxd -r -p 2>/dev/null); then
            echo "$decoded"
        fi
    fi
}

# --- URL DECODER ---
decode_url() {
    local in="$1"
    if [[ "$in" == *"%"* ]]; then
        if command -v python3 &>/dev/null; then
            python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read().strip()), end='')" < "$TMP_INPUT" 2>/dev/null
        else
            echo "$in" | sed 's/%20/ /g;s/%21/!/g;s/%3D/=/g;s/%2F/\//g;s/%3A/:/g;s/%40/@/g;s/%3F/?/g;s/%23/#/g'
        fi
    fi
}

# --- ROT-N BRUTE FORCE (ROT-1 through ROT-25) ---
decode_rot_brute() {
    local in="$1"
    # Only try if input looks like alphabetic text
    alpha_count=$(echo "$in" | tr -cd 'a-zA-Z' | wc -c)
    total_count=${#in}
    if [ "$total_count" -eq 0 ] || [ $(( alpha_count * 100 / total_count )) -lt 50 ]; then
        return
    fi

    local best_score=0
    local best_rot=0
    local best_text=""

    # Score each ROT using English letter frequency
    for n in $(seq 1 25); do
        rotated=$(echo "$in" | tr 'A-Za-z' "$(python3 -c "
alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
shifted = alpha[$n:26] + alpha[:$n] + alpha[26+$n:] + alpha[26:26+$n]
print(shifted)
" 2>/dev/null)")
        # Score: count common English words
        score=$(echo "$rotated" | grep -ioE '\b(the|and|is|in|to|of|a|it|that|for|on|with|as|are|was|be|at|by|have|from)\b' | wc -l)
        if [ "$score" -gt "$best_score" ]; then
            best_score=$score
            best_rot=$n
            best_text="$rotated"
        fi
    done

    if [ "$best_score" -gt 0 ]; then
        echo -e "${CYAN}[*] Best ROT: ROT-${best_rot} (score: ${best_score} English words)${NC}"
        echo "$best_text"
        check_for_flag "$best_text"
    fi
}

# --- CAESAR BRUTE FORCE (numeric shifts 1-25, only letters) ---
decode_caesar() {
    local in="$1"
    decode_rot_brute "$in"
}

# --- XOR BRUTE FORCE (via temp file, no inline injection) ---
decode_xor_fast() {
    if ! command -v python3 &>/dev/null; then
        return
    fi
    local max_len=1000
    python3 - "$TMP_INPUT" "$max_len" <<'PYEOF'
import sys

tmp_path = sys.argv[1]
max_len  = int(sys.argv[2])

with open(tmp_path, 'rb') as f:
    data = f.read(max_len)

# Single-byte XOR
found = []
for key in range(1, 256):
    decoded = bytes(b ^ key for b in data)
    printable = sum(32 <= b <= 126 for b in decoded)
    if len(decoded) == 0:
        continue
    ratio = printable / len(decoded)
    if ratio > 0.80:
        text = decoded.decode('utf-8', errors='replace')
        kws = ['flag', 'password', 'key', 'secret', 'ctf', 'thm', 'htb']
        if any(kw in text.lower() for kw in kws):
            found.append((f"Single-byte Key: {key} (0x{key:02x})", text))

# Multi-byte XOR (2-4 byte keys)
for key_len in range(2, 5):
    for k1 in range(1, 32):  # Limit search space
        for k2 in range(1, 32):
            if key_len == 2:
                key = bytes([k1, k2])
            else:
                continue  # Only do 2-byte for speed
            decoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
            printable = sum(32 <= b <= 126 for b in decoded)
            if len(decoded) == 0:
                continue
            if printable / len(decoded) > 0.85:
                text = decoded.decode('utf-8', errors='replace')
                kws = ['flag', 'password', 'key', 'secret', 'ctf', 'thm', 'htb']
                if any(kw in text.lower() for kw in kws):
                    key_hex = key.hex()
                    found.append((f"Multi-byte Key: 0x{key_hex}", text))

for label, text in found[:5]:
    print(label)
    print(text[:300])
    print("---")
PYEOF
}

# --- OCTAL DECODER ---
decode_octal() {
    local in="$1"
    if [[ "$in" =~ ^[0-7\ \\]+$ ]] && command -v perl &>/dev/null; then
        echo "$in" | perl -ne 'print pack("C*", map {oct} split /\s+/)'
    fi
}

# --- BINARY STRING DECODER (010110...) ---
decode_binary() {
    local in="$1"
    local clean
    clean=$(echo "$in" | tr -d '[:space:]')
    if [[ "$clean" =~ ^[01]+$ ]] && [ $(( ${#clean} % 8 )) -eq 0 ] && [ ${#clean} -ge 8 ]; then
        if command -v python3 &>/dev/null; then
            python3 - "$clean" <<'PYEOF'
import sys
bits = sys.argv[1]
chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
print(''.join(chars))
PYEOF
        fi
    fi
}

# --- MORSE CODE DECODER ---
decode_morse() {
    local in="$1"
    if ! [[ "$in" =~ ^[\.\-\ /]+$ ]] || [ ${#in} -lt 3 ]; then
        return
    fi
    if ! command -v python3 &>/dev/null; then
        return
    fi
    python3 - "$in" <<'PYEOF'
import sys

MORSE = {
    '.-':'A','-.-.':'C','-..-':'X','...-':'V','...--':'3',
    '-...':'B','-..':'D','-.--':'Y','--...':'7','....-':'4',
    '.':'E','..-..':'É','--.':'G','--..--':',',
    '..-.':'F','....':'H','.---':'J','-.-':'K','..--..':'?',
    '.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
    '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
    '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z',
    '.----':'1','..---':'2','...--':'3','....-':'4','.....' :'5',
    '-....':'6','--...':'7','---..':'8','----.':'9','-----':'0',
}

words = sys.argv[1].split('/')
decoded = []
for word in words:
    chars = []
    for code in word.strip().split():
        chars.append(MORSE.get(code, '?'))
    decoded.append(''.join(chars))

result = ' '.join(decoded)
print(result)
PYEOF
}

# --- HTML ENTITIES ---
decode_html() {
    local in="$1"
    if [[ "$in" == *"&#"* ]] || [[ "$in" == *"&lt;"* ]] || [[ "$in" == *"&amp;"* ]]; then
        if command -v python3 &>/dev/null; then
            python3 -c "
import html, sys
print(html.unescape(sys.stdin.read()), end='')
" < "$TMP_INPUT" 2>/dev/null
        elif command -v perl &>/dev/null; then
            echo "$in" | perl -MHTML::Entities -pe 'decode_entities($_);' 2>/dev/null
        fi
    fi
}

# --- RECURSIVE DECODER ---
recursive_decode() {
    local data="$1"
    local depth="${2:-0}"
    local max_depth=8

    [ "$depth" -ge "$max_depth" ] && { echo "$data"; return; }
    [ -z "$data" ] && return

    local decoded=""

    decoded=$(decode_base64 "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] Base64${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    decoded=$(decode_hex "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] Hex${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    decoded=$(decode_url "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] URL${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    decoded=$(decode_html "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] HTML entities${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    decoded=$(decode_binary "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] Binary${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    decoded=$(decode_morse "$data")
    if [ -n "$decoded" ] && [ "$decoded" != "$data" ]; then
        echo -e "${CYAN}[Layer $depth] Morse${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    fi

    echo -e "${GREEN}[*] Final (depth $depth):${NC}"
    echo "$data"
}

# --- HASH DETECTION ---
detect_hash() {
    local in="$1"
    local len=${#in}

    if [[ "$in" =~ ^[0-9a-fA-F]+$ ]]; then
        case $len in
            32) echo -e "${YELLOW}[+] Detected: MD5/NTLM/MD4 (32 chars)${NC}" ;;
            40) echo -e "${YELLOW}[+] Detected: SHA1 (40 chars)${NC}" ;;
            56) echo -e "${YELLOW}[+] Detected: SHA224 (56 chars)${NC}" ;;
            64) echo -e "${YELLOW}[+] Detected: SHA256 (64 chars)${NC}" ;;
            96) echo -e "${YELLOW}[+] Detected: SHA384 (96 chars)${NC}" ;;
            128) echo -e "${YELLOW}[+] Detected: SHA512 (128 chars)${NC}" ;;
            *) return ;;
        esac

        if command -v hashcat &>/dev/null; then
            local wordlist="/usr/share/wordlists/rockyou.txt"
            if [ -f "$wordlist" ]; then
                echo -e "${CYAN}[*] Attempting hashcat crack...${NC}"
                local mode
                case $len in 32) mode=0 ;; 40) mode=100 ;; 64) mode=1400 ;; 128) mode=1700 ;; *) mode=0 ;; esac
                local htmp
                htmp=$(mktemp)
                echo "$in" > "$htmp"
                timeout 30s hashcat -m "$mode" -a 0 "$htmp" "$wordlist" --quiet 2>/dev/null && \
                    hashcat -m "$mode" "$htmp" --show 2>/dev/null
                rm -f "$htmp"
            fi
        fi
    fi
}

# --- CRYPTO HEADER DETECTION ---
detect_crypto_headers() {
    local in="$1"
    [[ "$in" == "-----BEGIN PGP"*       ]] && echo -e "${YELLOW}[+] PGP Encrypted Message${NC}"
    [[ "$in" == "-----BEGIN OPENSSH"*   ]] && echo -e "${YELLOW}[+] OpenSSH Private Key${NC}"
    [[ "$in" == "-----BEGIN RSA"*       ]] && echo -e "${YELLOW}[+] RSA Private Key${NC}"
    [[ "$in" == "-----BEGIN EC"*        ]] && echo -e "${YELLOW}[+] EC Private Key${NC}"
    [[ "$in" == "-----BEGIN CERTIFICATE"* ]] && echo -e "${YELLOW}[+] X.509 Certificate${NC}"
    [[ "$in" =~ ^U2FsdGVkX1               ]] && echo -e "${YELLOW}[+] OpenSSL Encrypted Data (AES)${NC}"
    [[ "$in" =~ ^\$2[aby]\$              ]] && echo -e "${YELLOW}[+] bcrypt hash${NC}"
    [[ "$in" =~ ^\$argon2                ]] && echo -e "${YELLOW}[+] Argon2 hash${NC}"
}

# --- ESOTERIC: BRAINFUCK (via temp file, safe) ---
detect_brainfuck() {
    local in="$1"
    if [[ "$in" =~ ^[\+\-\<\>\[\]\.,]+$ ]] && [ ${#in} -gt 20 ]; then
        echo -e "${YELLOW}[+] Brainfuck code detected${NC}"
        if command -v python3 &>/dev/null; then
            echo -e "${CYAN}[*] Executing Brainfuck...${NC}"
            # Write code to temp file so we don't inject via heredoc
            local bf_tmp
            bf_tmp=$(mktemp)
            echo -n "$in" > "$bf_tmp"
            python3 - "$bf_tmp" <<'PYEOF'
import sys

with open(sys.argv[1]) as f:
    code = f.read().strip()

cells    = [0] * 30000
ptr      = 0
code_ptr = 0
output   = []
steps    = 0
max_steps = 1000000  # Prevent infinite loops

while code_ptr < len(code):
    cmd = code[code_ptr]
    if   cmd == '>': ptr += 1
    elif cmd == '<': ptr = max(0, ptr - 1)
    elif cmd == '+': cells[ptr] = (cells[ptr] + 1) % 256
    elif cmd == '-': cells[ptr] = (cells[ptr] - 1) % 256
    elif cmd == '.': output.append(chr(cells[ptr]))
    elif cmd == ',': pass
    elif cmd == '[' and cells[ptr] == 0:
        depth = 1
        while depth:
            code_ptr += 1
            if code[code_ptr] == '[': depth += 1
            elif code[code_ptr] == ']': depth -= 1
    elif cmd == ']' and cells[ptr] != 0:
        depth = 1
        while depth:
            code_ptr -= 1
            if code[code_ptr] == ']': depth += 1
            elif code[code_ptr] == '[': depth -= 1
    code_ptr += 1
    steps += 1
    if steps > max_steps:
        output.append('... [EXECUTION LIMIT REACHED]')
        break

print(''.join(output))
PYEOF
            rm -f "$bf_tmp"
        fi
    fi
}

# --- ATBASH CIPHER ---
decode_atbash() {
    local in="$1"
    # Only try if mostly alphabetic
    local alpha_count
    alpha_count=$(echo "$in" | tr -cd 'a-zA-Z' | wc -c)
    if [ "$alpha_count" -lt 5 ]; then
        return
    fi
    echo "$in" | tr 'A-Za-z' 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'
}

# --- VIGENERE DETECTION ---
decode_vigenere_detection() {
    local in="$1"
    if ! command -v python3 &>/dev/null; then
        return
    fi
    python3 - "$in" <<'PYEOF'
import sys, collections
text = ''.join(c.upper() for c in sys.argv[1] if c.isalpha())
if len(text) < 30:
    sys.exit(0)

# Kasiski examination - find repeated trigrams
trigrams = {}
for i in range(len(text) - 2):
    tri = text[i:i+3]
    if tri in trigrams:
        trigrams[tri].append(i)
    else:
        trigrams[tri] = [i]

repeated = {k: v for k, v in trigrams.items() if len(v) > 1}
if not repeated:
    sys.exit(0)

import math
distances = []
for positions in repeated.values():
    for i in range(len(positions) - 1):
        d = positions[i+1] - positions[i]
        if d > 0:
            distances.append(d)

if distances:
    gcd = distances[0]
    for d in distances[1:]:
        gcd = math.gcd(gcd, d)
    if 2 <= gcd <= 20:
        print(f"    Vigenere key length (Kasiski): likely {gcd}")
        print(f"    Repeated trigrams: {len(repeated)}")
PYEOF
}

# --- ZLIB/DEFLATE DETECTION ---
decode_zlib() {
    local in="$1"
    if ! command -v python3 &>/dev/null; then
        return
    fi
    python3 - "$TMP_INPUT" <<'PYEOF'
import sys, zlib
try:
    with open(sys.argv[1], 'rb') as f:
        data = f.read(10000)
    if data[:1] == b'\x78' and data[1:2] in (b'\x01', b'\x9c', b'\xda'):
        decompressed = zlib.decompress(data)
        text = decompressed.decode('utf-8', errors='replace')
        printable = sum(32 <= ord(c) <= 126 for c in text)
        if len(text) > 0 and printable / len(text) >= 0.5:
            print(f"zlib/deflate data decoded ({len(decompressed)} bytes)")
            print(text[:200])
except Exception:
    pass
PYEOF
}

# --- RAIL FENCE CIPHER ---
decode_rail_fence() {
    local in="$1"
    if ! command -v python3 &>/dev/null; then
        return
    fi
    python3 - "$in" <<'PYEOF'
import sys
text = sys.argv[1]
if len(text) < 10:
    sys.exit(0)

def rail_fence_decrypt(cipher, rails):
    n = len(cipher)
    fence = [['\n'] * n for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(n):
        fence[rail][i] = '*'
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    idx = 0
    for r in range(rails):
        for c in range(n):
            if fence[r][c] == '*' and idx < n:
                fence[r][c] = cipher[idx]
                idx += 1
    result = []
    rail, direction = 0, 1
    for i in range(n):
        result.append(fence[rail][i])
        if rail == 0: direction = 1
        elif rail == rails - 1: direction = -1
        rail += direction
    return ''.join(result)

common_words = ['the', 'and', 'is', 'in', 'to', 'of', 'a', 'it', 'for', 'on']
best_score, best_rails, best_text = 0, 0, ''
for rails in range(2, min(6, len(text))):
    decrypted = rail_fence_decrypt(text, rails)
    score = sum(1 for w in common_words if w in decrypted.lower())
    if score > best_score:
        best_score = score
        best_rails = rails
        best_text = decrypted

if best_score > 0:
    print(f"Rail Fence ({best_rails} rails, score: {best_score}): {best_text[:100]}")
PYEOF
}

# --- FREQUENCY ANALYSIS ---
frequency_analysis() {
    local in="$1"
    echo -e "${CYAN}[*] Letter Frequency Analysis:${NC}"
    echo "$in" | awk '{
        for(i=1;i<=length($0);i++) {
            c=substr($0,i,1)
            if(c ~ /[A-Za-z]/) freq[tolower(c)]++
        }
    } END {
        total=0
        for(c in freq) total+=freq[c]
        for(c in freq) printf "    %s: %d (%.1f%%)\n", c, freq[c], 100*freq[c]/total
    }' | sort -t: -k2 -rn | head -8
    echo -e "${YELLOW}    [i] English top: E T A O I N S H R${NC}"
}

# --- IC (INDEX OF COINCIDENCE) — distinguishes monoalpha from polyalpha ---
index_of_coincidence() {
    local in="$1"
    if command -v python3 &>/dev/null; then
        python3 - "$in" <<'PYEOF'
import sys, collections
text = ''.join(c.upper() for c in sys.argv[1] if c.isalpha())
if len(text) < 20:
    sys.exit(0)
freq = collections.Counter(text)
n = len(text)
ic = sum(v*(v-1) for v in freq.values()) / (n*(n-1)) if n > 1 else 0
print(f"    IC: {ic:.4f}  (English ~0.065, random ~0.038, Vigenere 0.04-0.06)")
if ic > 0.060:
    print("    -> Likely monoalphabetic substitution or plain English")
elif ic < 0.045:
    print("    -> Likely polyalphabetic / Vigenere / transposition")
else:
    print("    -> Inconclusive (could be weak substitution or short Vigenere)")
PYEOF
    fi
}

# --- QR/BARCODE SCAN ---
scan_qr_barcode() {
    local file="$1"
    if [ -f "$file" ] && file "$file" | grep -qi "image"; then
        if command -v zbarimg &>/dev/null; then
            echo -e "${CYAN}[*] Scanning for QR/barcodes...${NC}"
            if data=$(zbarimg --quiet --raw "$file" 2>/dev/null); then
                echo -e "${GREEN}[!!!] Found: $data${NC}"
                check_for_flag "$data"
            fi
        fi
    fi
}

# --- GPS COORDINATES ---
detect_gps() {
    local in="$1"
    if echo "$in" | grep -qE "[0-9]{1,3}\.[0-9]+[, ]+[0-9]{1,3}\.[0-9]+"; then
        coords=$(echo "$in" | grep -oE "[0-9]{1,3}\.[0-9]+[, ]+[0-9]{1,3}\.[0-9]+" | head -1)
        echo -e "${YELLOW}[+] GPS Coordinates: $coords${NC}"
        echo -e "${CYAN}    Map: https://www.google.com/maps?q=$coords${NC}"
    fi
}

# =============================================
# === MAIN ANALYSIS ===
# =============================================
echo -e "${BLUE}[*] Analyzing input (${#INPUT} chars)...${NC}\n"

detect_crypto_headers "$INPUT"
detect_hash "$INPUT"
detect_gps "$INPUT"

# File-specific
if [ "${IS_FILE:-false}" = true ]; then
    scan_qr_barcode "$1"
fi

# Esoteric
detect_brainfuck "$INPUT"

# XOR brute (for binary-looking data)
if [ ${#INPUT} -ge 30 ]; then
    echo -e "\n${BOLD}=== XOR Brute Force ===${NC}"
    decode_xor_fast
fi

# Recursive multi-layer decoding
echo -e "\n${BOLD}=== Recursive Decoding ===${NC}"
recursive_decode "$INPUT"

# Base32
echo -e "\n${BOLD}=== Base32 ===${NC}"
if decoded_b32=$(decode_base32 "$INPUT"); [ -n "$decoded_b32" ]; then
    echo -e "${GREEN}[+] Base32 decoded: $decoded_b32${NC}"
    check_for_flag "$decoded_b32"
else
    echo "    (Input does not match Base32 pattern)"
fi

# Base58
echo -e "\n${BOLD}=== Base58 ===${NC}"
if decoded_b58=$(decode_base58 "$INPUT"); [ -n "$decoded_b58" ]; then
    echo -e "${GREEN}[+] Base58 decoded: $decoded_b58${NC}"
    check_for_flag "$decoded_b58"
else
    echo "    (Input does not match Base58 pattern)"
fi

# ROT/Caesar brute
echo -e "\n${BOLD}=== Caesar / ROT Brute Force ===${NC}"
decode_rot_brute "$INPUT"

# Atbash
echo -e "\n${BOLD}=== Atbash Cipher ===${NC}"
if decoded_atbash=$(decode_atbash "$INPUT"); [ -n "$decoded_atbash" ]; then
    echo -e "${GREEN}[+] Atbash: $decoded_atbash${NC}"
    check_for_flag "$decoded_atbash"
else
    echo "    (Input too short for Atbash)"
fi

# Morse
echo -e "\n${BOLD}=== Morse Code ===${NC}"
if decoded_morse=$(decode_morse "$INPUT"); [ -n "$decoded_morse" ]; then
    echo -e "${GREEN}[+] Morse decoded: $decoded_morse${NC}"
    check_for_flag "$decoded_morse"
else
    echo "    (Input does not match Morse pattern)"
fi

# Binary string
echo -e "\n${BOLD}=== Binary String ===${NC}"
if decoded_bin=$(decode_binary "$INPUT"); [ -n "$decoded_bin" ]; then
    echo -e "${GREEN}[+] Binary decoded: $decoded_bin${NC}"
    check_for_flag "$decoded_bin"
else
    echo "    (Input does not match 8-bit binary pattern)"
fi

# Rail Fence
echo -e "\n${BOLD}=== Rail Fence Cipher ===${NC}"
if decoded_rail=$(decode_rail_fence "$INPUT"); [ -n "$decoded_rail" ]; then
    echo -e "${GREEN}[+] $decoded_rail${NC}"
else
    echo "    (No Rail Fence match)"
fi

# Zlib/deflate
echo -e "\n${BOLD}=== Compressed Data Detection ===${NC}"
if decoded_zlib=$(decode_zlib "$INPUT"); [ -n "$decoded_zlib" ]; then
    echo -e "${GREEN}[+] $decoded_zlib${NC}"
    check_for_flag "$decoded_zlib"
else
    echo "    (No zlib/deflate data detected)"
fi

# Frequency analysis for longer text
if [ ${#INPUT} -gt 80 ]; then
    echo
    frequency_analysis "$INPUT"
    index_of_coincidence "$INPUT"

    # Vigenère detection
    echo -e "\n${BOLD}=== Vigen\u00e8re Detection ===${NC}"
    if decoded_vig=$(decode_vigenere_detection "$INPUT"); [ -n "$decoded_vig" ]; then
        echo -e "${YELLOW}$decoded_vig${NC}"
    else
        echo "    (No Vigenere pattern detected)"
    fi
fi

echo -e "\n${GREEN}[\u2713] Analysis Complete${NC}"
