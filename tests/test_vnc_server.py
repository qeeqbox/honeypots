from __future__ import annotations

from multiprocessing import Process
from pathlib import Path
from time import sleep

import pytest
from vncdotool import api

from honeypots import QVNCServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    USERNAME,
    PASSWORD,
    wait_for_server,
)

PW_FILE = Path(__file__).parent / "data" / "pw_file"
PORT = "55900"


def _connect_to_vnc(port: str | None = None, password: str | None = None):
    client = api.connect(f"{IP}::{port or PORT}", username=USERNAME, password=password or PASSWORD)
    client.disconnect()


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QVNCServer, "port": PORT}],
    indirect=True,
)
def test_vnc_server(server_logs):
    # This VNC API creates a blocking daemon thread that can't be trivially stopped,
    # so we just run it in a process and terminate that instead
    with wait_for_server(PORT):
        sleep(0.2)  # somehow the server isn't ready sometimes even though the port is occupied
        process = Process(target=_connect_to_vnc)
        process.start()
    process.terminate()
    process.join(timeout=5)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connection, login = logs
    assert_connect_is_logged(connection, PORT)
    assert login["action"] == "login"
    assert login["status"] == "success"
    assert login["username"] == ""
    assert login["password"] == PASSWORD


PORT2 = str(int(PORT) + 1)
SERVER_CONFIG = {
    "honeypots": {
        "vnc": {
            "file_name": str(PW_FILE),
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QVNCServer, "port": PORT2, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_wrong_pw(server_logs):
    with wait_for_server(PORT2):
        sleep(0.2)  # somehow the server isn't ready sometimes even though the port is occupied
        process = Process(target=_connect_to_vnc, args=(PORT2, "foo"))
        process.start()
    process.terminate()
    process.join(timeout=5)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connection, login = logs
    assert_connect_is_logged(connection, PORT2)
    assert login["action"] == "login"
    assert login["status"] == "failed"
    assert login["username"] == ""
    assert login["password"] == "foo"
