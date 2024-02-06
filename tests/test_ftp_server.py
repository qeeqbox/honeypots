from __future__ import annotations

from ftplib import FTP

import pytest

from honeypots import QFTPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = "50021"
SERVER_CONFIG = {
    "honeypots": {
        "ftp": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QFTPServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_ftp_server(server_logs):
    with wait_for_server(PORT):
        client = FTP()
        client.connect(IP, int(PORT))
        client.login(USERNAME, PASSWORD)
        client.pwd()
        client.quit()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 6
    connect, cmd1, cmd2, login, cmd3, cmd4 = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert cmd1["data"] == {"args": f"('{USERNAME}',)", "cmd": "USER"}
    assert cmd2["data"] == {"args": f"('{PASSWORD}',)", "cmd": "PASS"}
    assert cmd3["data"] == {"args": "()", "cmd": "PWD"}
    assert cmd4["data"] == {"args": "()", "cmd": "QUIT"}
