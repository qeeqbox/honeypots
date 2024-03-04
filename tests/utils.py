from __future__ import annotations

import json
from contextlib import contextmanager
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM, socket
from time import sleep, time
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from pathlib import Path

IP = "127.0.0.1"
USERNAME = "test_user"
PASSWORD = "test_pw"
EXPECTED_KEYS = ("action", "dest_ip", "dest_port", "server", "src_ip", "src_port", "timestamp")


def load_logs_from_file(log_folder: Path) -> list[dict]:
    log_files = list(log_folder.iterdir())
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
    connection = None
    try:
        if udp:
            connection = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        else:
            connection = socket(AF_INET, SOCK_STREAM)
        connection.connect((host, int(port)))
        yield connection
    finally:
        if connection:
            connection.close()


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


@contextmanager
def wait_for_server(port: str | int):
    _wait_for_service(int(port))
    yield
    sleep(0.5)  # give the server process some time to write logs


def _wait_for_service(port: int, interval: float = 0.1, timeout: int = 5.0):
    start_time = time()
    while True:
        if _service_runs(port):
            return
        sleep(interval)
        if time() - start_time > timeout:
            raise TimeoutError()


def _service_runs(port: int) -> bool:
    return any(service.laddr.port == port for service in psutil.net_connections())
