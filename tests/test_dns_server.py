from __future__ import annotations

import pytest
from dns.resolver import Resolver

from honeypots import QDNSServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    wait_for_server,
)

PORT = "50053"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QDNSServer, "port": PORT}],
    indirect=True,
)
def test_dns_server(server_logs):
    with wait_for_server(PORT):
        resolver = Resolver(configure=False)
        resolver.nameservers = [IP]
        resolver.port = int(PORT)
        domain = "example.org"
        responses = [
            resolver.resolve(domain, "a", tcp=False),
            resolver.resolve(domain, "a", tcp=True),
        ]

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    connect, *queries = logs
    assert_connect_is_logged(connect, PORT)

    for query in queries:
        assert query["action"] == "query"
        assert "data" in query
        assert "<A address=" in query["data"]

    for response in responses:
        assert domain in response.canonical_name.to_text()
