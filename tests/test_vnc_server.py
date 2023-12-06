from __future__ import annotations

from multiprocessing import Process
from pathlib import Path
from time import sleep

import pytest
from vncdotool import api

from honeypots import QVNCServer
from .utils import find_free_port, load_logs_from_file

IP = "127.0.0.1"
PORT = str(find_free_port())
USERNAME = "testing"
PASSWORD = "testing"
EXPECTED_KEYS = ['action', 'dest_ip', 'dest_port', 'server', 'src_ip', 'src_port', 'timestamp']


@pytest.fixture
def server_logs(config_for_testing: Path):
    _server = QVNCServer(
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


def _connect_to_vnc():
    client = api.connect('{}::{}'.format(IP, PORT), password=PASSWORD)
    client.disconnect()


def test_vnc_server(server_logs):
    # This VNC API creates a blocking daemon thread that can't be trivially stopped,
    # so we just run it in a process and terminate that instead
    process = Process(target=_connect_to_vnc)
    process.start()
    sleep(1)  # give the server process some time to write logs
    process.terminate()
    process.join(timeout=5)

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 1
    assert all(k in logs[0] for k in EXPECTED_KEYS)
    assert logs[0]["dest_ip"] == IP
    assert logs[0]["dest_port"] == PORT
    assert logs[0]["action"] == "connection"
