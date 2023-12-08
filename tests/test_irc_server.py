from __future__ import annotations

from time import sleep

import pytest

from honeypots import QIRCServer
from .utils import (
    assert_connect_is_logged,
    connect_to,
    IP,
    load_logs_from_file,
    PASSWORD,
)

PORT = "56667"
SERVER_CONFIG = {
    "honeypots": {
        "irc": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QIRCServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_irc_server(server_logs):
    sleep(1)  # give the server some time to start

    with connect_to(IP, PORT) as connection:
        connection.setblocking(False)
        connection.send(f"PASS {PASSWORD}\n".encode())

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, command = logs
    assert_connect_is_logged(connect, PORT)

    assert command["action"] == "command"
    assert command["data"] == {"command": "PASS", "params": "['testing']", "prefix": ""}
