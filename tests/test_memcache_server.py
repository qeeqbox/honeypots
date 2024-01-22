from __future__ import annotations

import pytest

from honeypots import QMemcacheServer
from .utils import (
    assert_connect_is_logged,
    connect_to,
    IP,
    load_logs_from_file,
    wait_for_server,
)

PORT = "61211"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QMemcacheServer, "port": PORT}],
    indirect=True,
)
def test_memcache_server(server_logs):
    with wait_for_server(PORT), connect_to(IP, PORT) as connection:
        connection.send(b"stats\r\n")
        data, _ = connection.recvfrom(10000)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, stats = logs
    assert_connect_is_logged(connect, PORT)

    assert stats["action"] == "stats"

    assert b"STAT libevent 2.1.8-stable" in data
