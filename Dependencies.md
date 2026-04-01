All-in-One Installation:
  sudo apt update && sudo apt install -y file binutils xxd checksec libcap2-bin curl jq hashcat john bc python3 libimage-exiftool-perl binwalk steghide pngcheck sox ffmpeg imagemagick stegsnow zbar-tools outguess stegdetect perl foremost yara ssdeep ltrace strace gdb radare2 git xclip

  sudo gem install zsteg
  
  pip3 install pillow volatility3 python-registry pwntools ropper requests

---

Bin-Scout.sh:
  Dependencies: file, strings, xxd (required) | checksec, readelf, nm, ldd, getcap, objdump (optional)
  Install: 
  sudo apt install -y file binutils xxd checksec libcap2-bin


`Hash_`Detector.sh:
  Dependencies: grep, base64 (required) | curl, jq, hashcat, john (optional)
  Install: 
  sudo apt install -y curl jq hashcat john


`Header_`Fixer.sh:
  Dependencies: xxd, file, dd, bc (required) | python3 (optional)
  Install: 
  sudo apt install -y xxd bc python3


Stego-Hunt.sh:
  Dependencies: file, strings (required) | exiftool, binwalk, steghide, zsteg, pngcheck, sox, ffmpeg, stegdetect, outguess, imagemagick, stegsnow, zbarimg (optional)
  Install: 
  sudo apt install -y binutils libimage-exiftool-perl binwalk steghide pngcheck sox ffmpeg imagemagick stegsnow zbar-tools outguess stegdetect
  sudo gem install zsteg


Ultra-Analyzer.sh:
  Dependencies: base64, xxd, grep, awk, tr (required) | hashcat, zbarimg, python3, perl, bc (optional)
  Install: 
  sudo apt install -y xxd hashcat zbar-tools python3 perl bc


Forensics-Analyzer.py:
  Dependencies: file, strings (required) | exiftool, binwalk, foremost, yara, readelf, objdump, ssdeep, tlsh, volatility (optional)
  Install: 
  sudo apt install -y binutils libimage-exiftool-perl binwalk foremost yara ssdeep
  pip3 install pillow volatility3


Registry-Hunter.py:
  Dependencies: python-registry (required)
  Install: 
  pip3 install python-registry


Reverse-Engineer.py:
  Dependencies: file, strings (required) | objdump, readelf, nm, ltrace, strace, ROPgadget, ropper, gdb, radare2 (optional)
  Install: 
  sudo apt install -y binutils ltrace strace gdb radare2
  pip3 install pwntools ropper


Search-DB.py:
  Dependencies: sqlite3 (required) | requests (optional)
  Install: 
  pip3 install requests


Shell-Forger.py:
  Dependencies: python3 (required) | xclip (optional)
  Install: 
  sudo apt install -y xclip


Update-DB.py:
  Dependencies: sqlite3 (required) | git, requests, searchsploit (optional)
  Install: 
  sudo apt install -y git
  pip3 install requests
