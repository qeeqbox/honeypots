from __future__ import annotations

import json
from _socket import IPPROTO_UDP
from contextlib import contextmanager
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, socket

IP = "127.0.0.1"
USERNAME = "testing"
PASSWORD = "testing"
EXPECTED_KEYS = ("action", "dest_ip", "dest_port", "server", "src_ip", "src_port", "timestamp")


def load_logs_from_file(log_folder: Path) -> list[dict]:
    log_files = [f for f in log_folder.iterdir()]
    assert len(log_files) == 1
    log_file = log_files[0]
    logs = []
    for line in log_file.read_text().splitlines():
        if not line:
            continue
        logs.append(json.loads(line))
    return logs


@contextmanager
def connect_to(host: str, port: str, udp: bool = False) -> socket:
    client = None
    try:
        if udp:
            client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        else:
            client = socket(AF_INET, SOCK_STREAM)
        client.connect((host, int(port)))
        yield client
    finally:
        if client:
            client.close()


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
