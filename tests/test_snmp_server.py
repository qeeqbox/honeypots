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
    load_logs_from_file,
    wait_for_server,
)

PORT = "50161"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSNMPServer, "port": PORT}],
    indirect=True,
)
def test_snmp_server(server_logs):
    with wait_for_server(PORT):
        g = getCmd(
            SnmpEngine(),
            CommunityData("public"),
            UdpTransportTarget((IP, int(PORT))),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.4.1.9.9.618.1.4.1.0")),
        )
        next(g)

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
