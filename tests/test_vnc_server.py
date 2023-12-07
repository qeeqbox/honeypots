from __future__ import annotations

from multiprocessing import Process
from time import sleep

import pytest
from vncdotool import api

from honeypots import QVNCServer
from .utils import assert_connect_is_logged, IP, load_logs_from_file, PASSWORD

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
    process = Process(target=_connect_to_vnc)
    process.start()
    sleep(1)  # give the server process some time to write logs
    process.terminate()
    process.join(timeout=5)

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 1
    assert_connect_is_logged(logs[0], PORT)
