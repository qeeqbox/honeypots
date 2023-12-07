from __future__ import annotations

from contextlib import suppress
from socket import AF_INET, SOCK_STREAM, socket
from time import sleep

import pytest

from honeypots import QRDPServer
from .utils import (
    assert_connect_is_logged,
    connect_to, IP,
    load_logs_from_file,
)

PORT = "53389"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QRDPServer, "port": PORT}],
    indirect=True,
)
def test_rdp_server(server_logs):
    sleep(1)  # give the server some time to start

    with connect_to(IP, PORT) as connection:
        connection.send(b"test")
        connection.send(b"\x03\x00\x00*%\xe0\x00\x00\x00\x00\x00Cookie: mstshash=foobar\r\n\x01\x00\x08\x00\x03\x00\x00")

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, stshash = logs
    assert_connect_is_logged(connect, PORT)

    assert stshash["action"] == "stshash"
    assert stshash["mstshash"] == "success"
    assert "stshash" in stshash["data"]
    assert "foobar" in stshash["data"]["stshash"]
