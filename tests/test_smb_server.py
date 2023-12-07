from __future__ import annotations

from impacket.smbconnection import SMBConnection
from time import sleep

import pytest

from honeypots import QSMBServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50445"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSMBServer, "port": PORT}],
    indirect=True,
)
def test_smb_server(server_logs):
    sleep(5)  # give the server some time to start

    smb_client = SMBConnection(IP, IP, sess_port=PORT)
    smb_client.login(USERNAME, PASSWORD)
    smb_client.close()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    for entry in logs:
        assert_connect_is_logged(entry, PORT)

    assert "Incoming connection" in logs[0]["data"]
    assert "AUTHENTICATE_MESSAGE" in logs[1]["data"]
    assert "authenticated successfully" in logs[2]["data"]
