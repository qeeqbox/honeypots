from __future__ import annotations

import math
from struct import unpack
from time import sleep, time

import pytest

from honeypots import QNTPServer
from .utils import (
    connect_to,
    IP,
    load_logs_from_file,
)

PORT = "50123"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QNTPServer, "port": PORT}],
    indirect=True,
)
def test_ntp_server(server_logs):
    sleep(1)  # give the server some time to start

    with connect_to(IP, PORT, udp=True) as connection:
        connection.send(b"\x1b" + 47 * b"\0")
        data, _ = connection.recvfrom(256)
        output_time = unpack("!12I", data)[10] - 2208988800

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, query = logs
    assert all(k in connect for k in ["action", "server", "src_ip", "src_port", "timestamp"])
    assert connect["action"] == "connection"
    assert connect["src_ip"] == IP

    assert query["action"] == "query"
    assert query["status"] == "success"
    assert query["data"] == {"mode": "3", "version": "3"}

    assert math.isclose(output_time, time(), abs_tol=10)
