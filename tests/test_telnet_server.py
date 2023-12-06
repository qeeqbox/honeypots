from __future__ import annotations

from multiprocessing import Process
from pathlib import Path
from time import sleep

import pytest
from honeypots import QTelnetServer
from telnetlib import Telnet

from .utils import find_free_port, load_logs_from_file

IP = "127.0.0.1"
PORT = str(find_free_port())
USERNAME = "testing"
PASSWORD = "testing"
EXPECTED_KEYS = ['action', 'dest_ip', 'dest_port', 'server', 'src_ip', 'src_port', 'timestamp']


@pytest.fixture
def server_logs(config_for_testing: Path):
    _server = QTelnetServer(
        ip=IP,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        options="",
        config=str(config_for_testing.absolute()),
    )
    server_process = Process(target=_server.run_server)
    server_process.start()
    yield config_for_testing.parent / "logs"
    server_process.terminate()
    server_process.join()


def test_telnet_server(server_logs):
    telnet_client = Telnet(IP, int(PORT))
    telnet_client.read_until(b"login: ")
    telnet_client.write(USERNAME.encode() + b"\n")
    telnet_client.read_until(b"Password: ")
    telnet_client.write(PASSWORD.encode() + b"\n")
    sleep(1)  # give the server process some time to write logs

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 2
    assert all(k in logs[0] for k in EXPECTED_KEYS)
    assert logs[0]["dest_ip"] == IP
    assert logs[0]["dest_port"] == PORT
    assert logs[0]["action"] == "connection"

    assert all(k in logs[1] for k in ("username", "password"))
    assert logs[1]["action"] == "login"
    assert logs[1]["username"] == USERNAME
    assert logs[1]["password"] == PASSWORD
