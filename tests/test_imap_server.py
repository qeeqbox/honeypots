from __future__ import annotations

from contextlib import suppress
from imaplib import IMAP4

import pytest

from honeypots import QIMAPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
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
    with wait_for_server(PORT), suppress(IMAP4.error):
        imap_test = IMAP4(IP, int(PORT))
        imap_test.login(USERNAME, PASSWORD)

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
    assert cmd2["data"]["data"] == f'{USERNAME} "{PASSWORD}"'
