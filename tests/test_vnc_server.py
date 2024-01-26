from __future__ import annotations

from multiprocessing import Process

import pytest
from vncdotool import api

from honeypots import QVNCServer
from .utils import assert_connect_is_logged, IP, load_logs_from_file, PASSWORD, wait_for_server

PORT = "55900"


def _connect_to_vnc():
    client = api.connect(f"{IP}::{PORT}", password=PASSWORD)
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
        process = Process(target=_connect_to_vnc)
        process.start()
    process.terminate()
    process.join(timeout=5)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connection, login = logs
    assert_connect_is_logged(connection, PORT)
    assert login["action"] == "login"
    assert login["username"] == "None"  # FixMe: seems to be "None" even with a user
    assert login["password"]  # we can't check the PW because it is encrypted
