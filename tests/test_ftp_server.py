from __future__ import annotations

from ftplib import FTP
from time import sleep

import pytest

from honeypots import QFTPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged, IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
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
def test_http_proxy_server(server_logs):
    sleep(1)  # give the server some time to start

    client = FTP()
    client.connect(IP, int(PORT))
    client.login(USERNAME, PASSWORD)
    client.pwd()
    client.quit()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 6
    connect, cmd1, cmd2, login, cmd3, cmd4 = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert cmd1["data"] == {"args": "('testing',)", "cmd": "USER"}
    assert cmd2["data"] == {"args": "('testing',)", "cmd": "PASS"}
    assert cmd3["data"] == {"args": "()", "cmd": "PWD"}
    assert cmd4["data"] == {"args": "()", "cmd": "QUIT"}
