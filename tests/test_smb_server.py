from __future__ import annotations

import pytest
from impacket.smbconnection import SMBConnection

from honeypots import QSMBServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = "50445"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSMBServer, "port": PORT}],
    indirect=True,
)
def test_smb_server(server_logs):
    with wait_for_server(PORT):
        smb_client = SMBConnection(IP, IP, sess_port=PORT)
        smb_client.login(USERNAME, PASSWORD)
        smb_client.close()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    for entry in logs:
        assert_connect_is_logged(entry, PORT)

    assert "Incoming connection" in logs[0]["data"]
    assert "AUTHENTICATE_MESSAGE" in logs[1]["data"]
    assert "authenticated successfully" in logs[2]["data"]
