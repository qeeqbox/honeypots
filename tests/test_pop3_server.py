from __future__ import annotations

from contextlib import suppress
from poplib import error_proto, POP3
from time import sleep

import pytest

from honeypots import QPOP3Server
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50110"
SERVER_CONFIG = {
    "honeypots": {
        "pop3": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPOP3Server, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_pop3_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(error_proto):
        client = POP3(IP, int(PORT))
        client.user(USERNAME)
        client.pass_(PASSWORD)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 4
    connect, cmd1, cmd2, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert cmd1["action"] == "command"
    assert cmd1["data"] == {"args": "testing", "cmd": "USER"}
    assert cmd2["action"] == "command"
    assert cmd2["data"] == {"args": "testing", "cmd": "PASS"}
