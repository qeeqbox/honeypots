from __future__ import annotations

import json
import socket
from pathlib import Path


def find_free_port(start_port: int = 50_000, end_port: int = 60_000, sock_type: int = socket.SOCK_STREAM) -> int:
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, sock_type) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                pass
    raise Exception("No free port found")


def load_logs_from_file(file: Path) -> list[dict]:
    logs = []
    for line in file.read_text().splitlines():
        if not line:
            continue
        logs.append(json.loads(line))
    return logs
