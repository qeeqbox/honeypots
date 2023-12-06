from __future__ import annotations

import json
from multiprocessing import Process
from pathlib import Path
from time import sleep

import pytest
from honeypots import QSSHServer
from paramiko import SSHClient, AutoAddPolicy

from .utils import find_free_port, load_logs_from_file

IP = "127.0.0.1"
PORT = find_free_port()
USERNAME = "testing"
PASSWORD = "testing"
EXPECTED_KEYS = ["action", "dest_ip", "dest_port", "server", "src_ip", "src_port", "timestamp"]
SERVER_CONFIG = {
    "honeypots": {
        "ssh": {
            "backup_count": 10,
            "ip": IP,
            "log_file_name": "ssh.jsonl",
            "max_bytes": 10000,
            "options": ["capture_commands"],
            "password": PASSWORD,
            "port": str(PORT),
            "username": USERNAME,
        },
    }
}


@pytest.fixture
def custom_config(config_for_testing: Path):
    config = json.loads(config_for_testing.read_text())
    config.update(SERVER_CONFIG)
    config_for_testing.write_text(json.dumps(config))
    yield config_for_testing


@pytest.fixture
def server_logs(custom_config: Path):
    _server = QSSHServer(
        ip=IP,
        port=str(PORT),
        username=USERNAME,
        password=PASSWORD,
        options="",
        config=str(custom_config.absolute()),
    )
    server_process = Process(target=_server.run_server)
    server_process.start()
    yield custom_config.parent / "logs"
    server_process.terminate()
    server_process.join()


def test_ssh_server(server_logs):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(IP, port=PORT, username=USERNAME, password=PASSWORD)
    ssh.close()
    sleep(1)  # give the server process some time to write logs

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 2
    assert all(k in logs[0] for k in EXPECTED_KEYS)
    assert logs[0]["dest_ip"] == IP
    assert logs[0]["dest_port"] == str(PORT)
    assert logs[0]["action"] == "connection"

    assert logs[1]["action"] == "login"
    assert logs[1]["username"] == USERNAME
