from __future__ import annotations

from telnetlib import Telnet
from time import sleep

import pytest

from honeypots import QTelnetServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50023"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QTelnetServer, "port": PORT}],
    indirect=True,
)
def test_telnet_server(server_logs):
    sleep(1)  # give the server some time to start

    telnet_client = Telnet(IP, int(PORT))
    telnet_client.read_until(b"login: ")
    telnet_client.write(USERNAME.encode() + b"\n")
    telnet_client.read_until(b"Password: ")
    telnet_client.write(PASSWORD.encode() + b"\n")

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
