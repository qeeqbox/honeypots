from __future__ import annotations

import pytest

from honeypots import QIRCServer
from .utils import (
    assert_connect_is_logged,
    connect_to,
    IP,
    load_logs_from_file,
    PASSWORD,
    wait_for_server,
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
    with wait_for_server(PORT), connect_to(IP, PORT) as connection:
        connection.setblocking(False)
        connection.send(f"PASS {PASSWORD}\n".encode())

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, command = logs
    assert_connect_is_logged(connect, PORT)

    assert command["action"] == "command"
    assert command["data"] == {"command": "PASS", "params": f"['{PASSWORD}']", "prefix": ""}
