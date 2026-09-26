#!/usr/bin/env bash
# Send one HMP command to the running VM's monitor and print the reply.
#   scripts/monitor.sh "info pci"
#   scripts/monitor.sh "info pci"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 - "$ROOT/build/vm/monitor.sock" "$*" <<'EOF'
import socket, sys
sock_path, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX)
s.connect(sock_path)

def until_prompt():
    buf = b""
    while not buf.endswith(b"(qemu) "):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace")

until_prompt()                          # banner
s.sendall(cmd.encode() + b"\n")
out = until_prompt()
# HMP echoes the command line (with terminal escapes); drop the first line
lines = out.replace("\r", "").split("\n")[1:-1]
print("\n".join(lines))
EOF
