from __future__ import annotations

from time import sleep

import pytest
from dns.resolver import Resolver

from honeypots import QDNSServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
)

PORT = "50053"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDNSServer, "port": PORT}],
    indirect=True,
)
def test_dns_server(server_logs):
    sleep(1)  # give the server some time to start

    resolver = Resolver(configure=False)
    resolver.nameservers = [IP]
    resolver.port = int(PORT)
    domain = "example.org"
    response = resolver.resolve(domain, "a")

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, query = logs
    assert_connect_is_logged(connect, PORT)

    assert query["action"] == "query"
    assert "data" in query
    assert "<A address=" in query["data"]

    assert domain in response.canonical_name.to_text()
