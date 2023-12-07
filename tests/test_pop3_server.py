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


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPOP3Server, "port": PORT}],
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

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
