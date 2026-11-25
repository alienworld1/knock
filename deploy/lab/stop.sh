#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  echo 'Usage: deploy/lab/stop.sh LAB_DIRECTORY' >&2
  exit 2
fi

python3 - "$1" <<'PY'
import socket
import sys
from pathlib import Path

lab = Path(sys.argv[1])
for role in ("door", "requester", "outsider"):
    monitor = lab / role / "monitor.sock"
    if monitor.is_socket():
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(monitor))
            connection.sendall(b"system_powerdown\n")
            connection.recv(4096)
PY
