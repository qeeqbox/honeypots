from __future__ import annotations

import pytest
from socket import socket

from honeypots import QTelnetServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
    connect_to
)

PORT = "50023"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QTelnetServer, "port": PORT}],
    indirect=True,
)

def test_telnet_server(server_logs):
    with wait_for_server(PORT), connect_to(IP, PORT) as connection:
        data, _ = connection.recvfrom(10000)
        connection.send(USERNAME.encode() + b"\n")
        data, _ = connection.recvfrom(10000)
        connection.send(PASSWORD.encode() + b"\n")

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect_, login = logs
    assert_connect_is_logged(connect_, PORT)
    assert_login_is_logged(login)