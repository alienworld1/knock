#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  echo 'Usage: deploy/lab/stop.sh LAB_DIRECTORY' >&2
  exit 2
fi

python3 - "$1" <<'PY'
import socket
import sys
import time
from pathlib import Path

def read_prompt(connection):
    data = bytearray()
    while b"(qemu)" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise EOFError("QEMU monitor disconnected")
        data.extend(chunk)
        if len(data) > 16384:
            raise RuntimeError("Unexpected QEMU monitor response")


lab = Path(sys.argv[1])
stopping = []
for role in ("door", "requester", "outsider", "requester2"):
    guest = lab / role
    monitor = guest / "monitor.sock"
    if not monitor.is_socket():
        continue
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        try:
            connection.connect(str(monitor))
        except ConnectionRefusedError:
            # QEMU can leave its monitor socket behind after shutdown.
            continue
        read_prompt(connection)
        connection.sendall(b"system_powerdown\r")
        try:
            read_prompt(connection)
        except EOFError:
            pass  # A guest may exit before the monitor can acknowledge.
    stopping.append(guest / "qemu.pid")

deadline = time.monotonic() + 45
while any(pidfile.exists() for pidfile in stopping):
    if time.monotonic() >= deadline:
        raise SystemExit("Timed out waiting for the Knock guests to shut down")
    time.sleep(1)
PY
