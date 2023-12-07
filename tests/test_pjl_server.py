from __future__ import annotations

from socket import AF_INET, SOCK_STREAM, socket
from time import sleep

import pytest

from honeypots import QPJLServer
from .utils import (
    assert_connect_is_logged,
    connect_to, IP,
    load_logs_from_file,
)

PORT = "59100"
SERVER_CONFIG = {
    "honeypots": {
        "pjl": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPJLServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_pjl_server(server_logs):
    sleep(1)  # give the server some time to start

    with connect_to(IP, PORT) as connection:
        connection.send(b'\x1b%-12345X@PJL prodinfo')

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, query = logs
    assert_connect_is_logged(connect, PORT)

    assert query["action"] == "query"
    assert query["data"] == {"command": "@PJL prodinfo"}
    assert query["status"] == "success"
