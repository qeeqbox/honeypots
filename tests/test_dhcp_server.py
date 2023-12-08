from __future__ import annotations

from time import sleep

import pytest

from honeypots import QDHCPServer
from .utils import (
    connect_to,
    EXPECTED_KEYS,
    IP,
    load_logs_from_file,
)

PORT = "50067"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDHCPServer, "port": PORT}],
    indirect=True,
)
def test_dhcp_server(server_logs):
    sleep(1)  # give the server some time to start

    with connect_to(IP, PORT, udp=True) as connection:
        connection.send(b"\x03" * 240)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 1
    (query,) = logs
    assert all(k in query for k in EXPECTED_KEYS)
    assert query["action"] == "query"
    assert query["status"] == "success"
    assert query["data"] == {"mac_address": "03:03:03:03:03:03"}
