#!/bin/bash

echo '''
8   8                                                                                                                                        
8   8 eeeee eeeee eeee eeeee  eeeee eeeeeee eeeee  e     eeee    eeeee e   e eeee    eeeee eeee eeeee  eeeee eeeeeee eeeee  e     eeee eeeee 
8e  8 8   8 8   " 8  8 8   8  8   8 8  8  8 8   8  8     8         8   8   8 8       8   " 8  8 8   8  8   8 8  8  8 8   8  8     8    8   8 
88  8 8e  8 8eeee 8e   8eee8e 8eee8 8e 8  8 8eee8e 8e    8eee      8e  8eee8 8eee    8eeee 8e   8eee8e 8eee8 8e 8  8 8eee8e 8e    8eee 8e  8 
88  8 88  8    88 88   88   8 88  8 88 8  8 88   8 88    88        88  88  8 88         88 88   88   8 88  8 88 8  8 88   8 88    88   88  8 
88ee8 88  8 8ee88 88e8 88   8 88  8 88 8  8 88eee8 88eee 88ee      88  88  8 88ee    8ee88 88e8 88   8 88  8 88 8  8 88eee8 88eee 88ee 88ee8 
                                                                                                                                             
'''
set -euo pipefail

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
)

OPTIONAL_TOOLS=(
    "hashcat:hashcat"
    "zbarimg:zbar-tools"
    "python3:python3"
    "perl:perl"
)

# --- DEPENDENCY CHECK ---
check_dependencies() {
    local missing_required=()
    local missing_optional=()
    local all_good=true
    
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    for entry in "${REQUIRED_TOOLS[@]}"; do
        IFS=':' read -r tool package <<< "$entry"
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool ($package)")
            all_good=false
        fi
    done
    
    for entry in "${OPTIONAL_TOOLS[@]}"; do
        IFS=':' read -r tool package <<< "$entry"
        if ! command -v "$tool" &>/dev/null; then
            missing_optional+=("$tool ($package)")
        fi
    done
    
    if [ "$all_good" = true ] && [ ${#missing_optional[@]} -eq 0 ]; then
        echo -e "${GREEN}[✓] All dependencies satisfied!${NC}\n"
        return 0
    fi
    
    if [ ${#missing_required[@]} -gt 0 ]; then
        echo -e "${RED}[✗] MISSING REQUIRED DEPENDENCIES:${NC}"
        printf '%s\n' "${missing_required[@]}" | sed 's/^/    /'
        
        local packages=()
        for entry in "${REQUIRED_TOOLS[@]}"; do
            IFS=':' read -r tool package <<< "$entry"
            if ! command -v "$tool" &>/dev/null; then
                packages+=("$package")
            fi
        done
        packages=($(printf '%s\n' "${packages[@]}" | sort -u))
        
        echo -e "\n${YELLOW}Install with:${NC}"
        echo -e "    ${BOLD}sudo apt install ${packages[*]}${NC}\n"
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing optional tools:${NC}"
        printf '%s\n' "${missing_optional[@]}" | sed 's/^/    /'
        echo -e "${CYAN}(hashcat: hash cracking, python3: advanced decoding)${NC}\n"
    else
        echo -e "${GREEN}[✓] All dependencies satisfied!${NC}\n"
    fi
}

check_dependencies

# --- INPUT HANDLING ---
if [ "$#" -ge 1 ]; then
    if [ -f "$1" ]; then
        INPUT=$(cat "$1")
    else
        INPUT="$1"
    fi
else
    if [ ! -t 0 ]; then
        INPUT=$(cat)
    else
        echo -e "${RED}Usage: $0 <string|file>${NC}"
        exit 1
    fi
fi

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

# --- EARLY EXIT ON FLAG DETECTION ---
check_for_flag() {
    local text="$1"
    if echo "$text" | grep -qiE "(flag|ctf|thm|htb|picoctf)\{"; then
        FLAG=$(echo "$text" | grep -oE '(flag|FLAG|ctf|CTF|thm|THM|htb|HTB|picoCTF|picoctf)\{[^}]+\}')
        echo -e "${GREEN}${BOLD}[!!!] FLAG FOUND: $FLAG${NC}"
        exit 0
    fi
}

# --- OPTIMIZED BASE64 DETECTION ---
decode_base64() {
    local in="$1"
    
    # Check cache
    if cached_result=$(cached_decode "b64" "$in"); then
        echo "$cached_result"
        return
    fi
    
    if [[ "$in" =~ ^[A-Za-z0-9+/=]+$ ]] && [ ${#in} -ge 8 ]; then
        if decoded=$(echo "$in" | base64 -d 2>/dev/null); then
            save_decode_cache "b64" "$in" "$decoded"
            echo "$decoded"
        fi
    fi
}

# --- OPTIMIZED XOR (Python for speed) ---
decode_xor_fast() {
    local in="$1"
    local max_len=500  # Only scan first 500 bytes for speed
    
    if command -v python3 &>/dev/null; then
        python3 <<PYXOR
import sys
data = """$in"""[:$max_len].encode('utf-8', errors='ignore')

for key in range(1, 256):
    decoded = bytes(b ^ key for b in data)
    # Check if mostly printable
    printable = sum(32 <= b <= 126 for b in decoded)
    if printable / len(decoded) > 0.85:
        result = decoded.decode('utf-8', errors='ignore')
        if any(keyword in result.lower() for keyword in ['flag', 'password', 'key', 'secret']):
            print(f"XOR Key: {key} (0x{key:02x})")
            print(result)
            sys.exit(0)
PYXOR
    fi
}

# --- HEX DECODER ---
decode_hex() {
    local in="$1"
    
    if [[ "$in" =~ ^[0-9a-fA-F]+$ ]] && [ $((${#in} % 2)) -eq 0 ]; then
        if decoded=$(echo "$in" | xxd -r -p 2>/dev/null); then
            echo "$decoded"
        fi
    fi
}

# --- URL DECODER ---
decode_url() {
    local in="$1"
    
    if [[ "$in" == *"%"* ]]; then
        if command -v python3 &>/dev/null; then
            python3 -c "import urllib.parse; print(urllib.parse.unquote('$in'))" 2>/dev/null
        else
            # Bash fallback (basic)
            echo "$in" | sed 's/%20/ /g;s/%21/!/g;s/%3D/=/g'
        fi
    fi
}

# --- OCTAL DECODER ---
decode_octal() {
    local in="$1"
    
    if [[ "$in" =~ ^[0-7\ \\]+$ ]]; then
        if command -v perl &>/dev/null; then
            echo "$in" | perl -ne 'print pack("C*", map {oct} split /\\s+/)'
        fi
    fi
}

# --- HTML ENTITIES ---
decode_html() {
    local in="$1"
    
    if [[ "$in" == *"&#"* ]] || [[ "$in" == *"&lt;"* ]]; then
        if command -v perl &>/dev/null; then
            echo "$in" | perl -MHTML::Entities -pe 'decode_entities($_);' 2>/dev/null
        else
            # Basic substitutions
            echo "$in" | sed 's/&lt;/</g;s/&gt;/>/g;s/&amp;/\&/g;s/&quot;/"/g'
        fi
    fi
}

# --- RECURSIVE DECODER (with depth limit) ---
recursive_decode() {
    local data="$1"
    local depth="${2:-0}"
    local max_depth=5
    
    [ $depth -ge $max_depth ] && echo "$data" && return
    
    local decoded=""
    
    # Try each decoder
    decoded=$(decode_base64 "$data")
    [ -n "$decoded" ] && [ "$decoded" != "$data" ] && {
        echo -e "${CYAN}[Layer $depth] Base64 decoded${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    }
    
    decoded=$(decode_hex "$data")
    [ -n "$decoded" ] && [ "$decoded" != "$data" ] && {
        echo -e "${CYAN}[Layer $depth] Hex decoded${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    }
    
    decoded=$(decode_url "$data")
    [ -n "$decoded" ] && [ "$decoded" != "$data" ] && {
        echo -e "${CYAN}[Layer $depth] URL decoded${NC}"
        check_for_flag "$decoded"
        recursive_decode "$decoded" $((depth + 1))
        return
    }
    
    # No more layers
    echo -e "${GREEN}[*] Final decoded result:${NC}"
    echo "$data"
}

# --- HASH DETECTION ---
detect_hash() {
    local in="$1"
    local len=${#in}
    
    if [[ "$in" =~ ^[0-9a-fA-F]+$ ]]; then
        case $len in
            32) echo -e "${YELLOW}[+] Detected: MD5 hash (32 chars)${NC}" ;;
            40) echo -e "${YELLOW}[+] Detected: SHA1 hash (40 chars)${NC}" ;;
            64) echo -e "${YELLOW}[+] Detected: SHA256 hash (64 chars)${NC}" ;;
            128) echo -e "${YELLOW}[+] Detected: SHA512 hash (128 chars)${NC}" ;;
            *) return ;;
        esac
        
        # Attempt hashcat cracking if available
        if command -v hashcat &>/dev/null; then
            local wordlist="/usr/share/wordlists/rockyou.txt"
            
            if [ -f "$wordlist" ]; then
                echo -e "${CYAN}[*] Attempting hashcat crack...${NC}"
                
                local mode
                case $len in
                    32) mode=0 ;;
                    40) mode=100 ;;
                    64) mode=1400 ;;
                    128) mode=1700 ;;
                esac
                
                echo "$in" > /tmp/hash_$$
                timeout 30s hashcat -m $mode -a 0 /tmp/hash_$$ "$wordlist" --quiet 2>/dev/null && {
                    hashcat -m $mode /tmp/hash_$$ --show 2>/dev/null
                }
                rm -f /tmp/hash_$$
            fi
        fi
    fi
}

# --- CRYPTO HEADER DETECTION ---
detect_crypto_headers() {
    local in="$1"
    
    [[ "$in" == "-----BEGIN PGP"* ]] && echo -e "${YELLOW}[+] PGP Encrypted Message${NC}"
    [[ "$in" == "-----BEGIN OPENSSH"* ]] && echo -e "${YELLOW}[+] OpenSSH Private Key${NC}"
    [[ "$in" == "-----BEGIN RSA"* ]] && echo -e "${YELLOW}[+] RSA Private Key${NC}"
    [[ "$in" == "-----BEGIN CERTIFICATE"* ]] && echo -e "${YELLOW}[+] X.509 Certificate${NC}"
    [[ "$in" =~ ^U2FsdGVkX1 ]] && echo -e "${YELLOW}[+] OpenSSL Encrypted Data${NC}"
}

# --- ESOTERIC LANGUAGES ---
detect_brainfuck() {
    local in="$1"
    
    if [[ "$in" =~ ^[\+\-\<\>\[\]\.,]+$ ]] && [ ${#in} -gt 20 ]; then
        echo -e "${YELLOW}[+] Brainfuck code detected${NC}"
        
        if command -v python3 &>/dev/null; then
            echo -e "${CYAN}[*] Executing Brainfuck...${NC}"
            python3 <<'PYBF'
import sys
code = """$in"""
cells = [0] * 30000
ptr = 0
code_ptr = 0
output = []

while code_ptr < len(code):
    cmd = code[code_ptr]
    if cmd == '>': ptr += 1
    elif cmd == '<': ptr -= 1
    elif cmd == '+': cells[ptr] = (cells[ptr] + 1) % 256
    elif cmd == '-': cells[ptr] = (cells[ptr] - 1) % 256
    elif cmd == '.': output.append(chr(cells[ptr]))
    elif cmd == '[' and cells[ptr] == 0:
        depth = 1
        while depth > 0:
            code_ptr += 1
            if code[code_ptr] == '[': depth += 1
            elif code[code_ptr] == ']': depth -= 1
    elif cmd == ']' and cells[ptr] != 0:
        depth = 1
        while depth > 0:
            code_ptr -= 1
            if code[code_ptr] == ']': depth += 1
            elif code[code_ptr] == '[': depth -= 1
    code_ptr += 1

print(''.join(output))
PYBF
        fi
    fi
}

# --- FREQUENCY ANALYSIS (optimized with awk) ---
frequency_analysis() {
    local in="$1"
    
    echo -e "${CYAN}[*] Character Frequency Analysis:${NC}"
    
    echo "$in" | awk '{
        for(i=1;i<=length($0);i++) {
            c=substr($0,i,1)
            if(c ~ /[A-Za-z]/) freq[tolower(c)]++
        }
    } END {
        for(c in freq) print freq[c], c
    }' | sort -rn | head -5
    
    # English frequency: E T A O I N
    echo -e "${YELLOW}[i] Common English letters: E T A O I N${NC}"
    echo -e "${YELLOW}[i] If significantly different → substitution cipher${NC}"
}

# --- QR/BARCODE SCANNING (for image files) ---
scan_qr_barcode() {
    local file="$1"
    
    if [ -f "$file" ] && file "$file" | grep -qi "image"; then
        if command -v zbarimg &>/dev/null; then
            echo -e "${CYAN}[*] Scanning for QR codes/barcodes...${NC}"
            if data=$(zbarimg --quiet --raw "$file" 2>/dev/null); then
                echo -e "${GREEN}[!!!] FOUND: $data${NC}"
                check_for_flag "$data"
            fi
        fi
    fi
}

# --- GPS COORDINATES ---
detect_gps() {
    local in="$1"
    
    if echo "$in" | grep -qE "[0-9]{1,3}\.[0-9]+[,\s]+[0-9]{1,3}\.[0-9]+"; then
        coords=$(echo "$in" | grep -oE "[0-9]{1,3}\.[0-9]+[,\s]+[0-9]{1,3}\.[0-9]+" | head -1)
        echo -e "${YELLOW}[+] GPS Coordinates detected: $coords${NC}"
        echo -e "${CYAN}    View on map: https://www.google.com/maps?q=$coords${NC}"
    fi
}

# === MAIN ANALYSIS ===
echo -e "${BLUE}[*] Analyzing input (${#INPUT} chars)...${NC}\n"

# Quick checks
detect_crypto_headers "$INPUT"
detect_hash "$INPUT"
detect_gps "$INPUT"

# Try QR scan if file
if [ -f "$1" ] 2>/dev/null; then
    scan_qr_barcode "$1"
fi

# Brainfuck detection
detect_brainfuck "$INPUT"

# XOR brute-force (for binary-looking data)
if [ ${#INPUT} -gt 50 ]; then
    decode_xor_fast "$INPUT"
fi

# Recursive decoding
echo -e "\n${BOLD}=== Recursive Decoding ===${NC}"
recursive_decode "$INPUT"

# Frequency analysis (for longer text)
if [ ${#INPUT} -gt 100 ]; then
    echo
    frequency_analysis "$INPUT"
fi

echo -e "\n${GREEN}[✓] Analysis Complete${NC}"
