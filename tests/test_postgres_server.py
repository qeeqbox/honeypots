from __future__ import annotations

from contextlib import suppress

import pytest
from socket import socket

from honeypots import QPostgresServer
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

PORT = "55432"

@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPostgresServer, "port": PORT}],
    indirect=True,
)
def test_postgres_server(server_logs):
    with wait_for_server(PORT), connect_to(IP, PORT) as connection:
        connection.send(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
        data, _ = connection.recvfrom(10000)
        connection.send(b'\x00\x00\x00\x21\x00\x03\x00\x00\x75\x73\x65\x72\x00' + USERNAME.encode() + b'\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00' + USERNAME.encode() + b'\x00\x00')
        data, _ = connection.recvfrom(10000)
        connection.send(b'\x70\x00\x00\x00\x09' + PASSWORD.encode() + b'\x00')

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect_, login = logs
    assert_connect_is_logged(connect_, PORT)
    assert_login_is_logged(login)