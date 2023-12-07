from __future__ import annotations

import pytest
from pysnmp.hlapi import CommunityData, ContextData, getCmd, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget

from honeypots import QSNMPServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
)

PORT = "50161"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSNMPServer, "port": PORT}],
    indirect=True,
)
def test_snmp_server(server_logs):
    g = getCmd(
        SnmpEngine(),
        CommunityData("public"),
        UdpTransportTarget((IP, int(PORT))),
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.4.1.9.9.618.1.4.1.0")),
    )
    next(g)

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) >= 2
    connect, query, *_ = logs
    assert_connect_is_logged(connect, PORT)

    assert query["action"] == "query"
    assert query["data"] == {"community": "public", "oids": "1.3.6.1.4.1.9.9.618.1.4.1.0", "version": "1"}
