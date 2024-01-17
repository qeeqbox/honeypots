from __future__ import annotations

from contextlib import suppress
from imaplib import IMAP4
from time import sleep

import pytest

from honeypots import QIMAPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50143"
SERVER_CONFIG = {
    "honeypots": {
        "imap": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QIMAPServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_imap_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(IMAP4.error):
        imap_test = IMAP4(IP, int(PORT))
        imap_test.login(USERNAME, PASSWORD)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 4
    connect, cmd1, cmd2, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert cmd1["action"] == "command"
    assert cmd1["data"]["cmd"] == "CAPABILITY"
    assert cmd1["data"]["data"] == "None"

    assert cmd2["action"] == "command"
    assert cmd2["data"]["cmd"] == "LOGIN"
    assert cmd2["data"]["data"] == 'testing "testing"'
