from __future__ import annotations

import json
from pathlib import Path

IP = "127.0.0.1"
USERNAME = "testing"
PASSWORD = "testing"
EXPECTED_KEYS = ("action", "dest_ip", "dest_port", "server", "src_ip", "src_port", "timestamp")


def load_logs_from_file(file: Path) -> list[dict]:
    logs = []
    for line in file.read_text().splitlines():
        if not line:
            continue
        logs.append(json.loads(line))
    return logs


def assert_connect_is_logged(
    connect: dict[str, str], port: str, expected_keys: list[str] | tuple[str, ...] = EXPECTED_KEYS
):
    assert all(k in connect for k in expected_keys)
    assert connect["dest_ip"] == IP
    assert connect["dest_port"] == port
    assert connect["action"] == "connection"


def assert_login_is_logged(login: dict[str, str]):
    assert all(k in login for k in ("username", "password"))
    assert login["action"] == "login"
    assert login["username"] == USERNAME
    assert login["password"] == PASSWORD
    assert login["status"] == "success"
