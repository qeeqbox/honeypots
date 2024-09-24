from __future__ import annotations

import pytest
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    getCmd,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
)

from honeypots import QSNMPServer
from .utils import (
    assert_connect_is_logged,
    IP,
    connect_to,
    load_logs_from_file,
    wait_for_server,
)

PORT = "50161"

@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSNMPServer, "port": PORT}],
    indirect=True,
)
def test_postgres_server(server_logs):
    with wait_for_server(PORT), connect_to(IP, PORT, udp=True) as connection:
        connection.send(b'\x30\x2e\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x21\x02\x04\x00\xab\x61\x67\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0d\x2b\x06\x01\x04\x01\x09\x09\x84\x6a\x01\x04\x01\x00\x05\x00')

    logs = load_logs_from_file(server_logs)

    assert len(logs) >= 2
    connect, query, *_ = logs
    assert_connect_is_logged(connect, PORT)

    assert query["action"] == "query"
    assert query["data"] == {
        "community": "public",
        "oids": "1.3.6.1.4.1.9.9.618.1.4.1.0",
        "version": "1",
    }
