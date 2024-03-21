from __future__ import annotations

from base64 import b64decode
from smtplib import SMTP

import pytest

from honeypots import QSMTPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = "50025"
SERVER_CONFIG = {
    "honeypots": {
        "smtp": {
            "options": ["capture_commands"],
        },
    }
}
EXPECTED_DATA = [
    {"arg": "FROM:<fromtest>", "command": "mail", "data": "None"},
    {"arg": "TO:<totest>", "command": "rcpt", "data": "None"},
    {"arg": "None", "command": "data", "data": "None"},
    {"arg": "None", "command": "Nothing", "data": "None"},
    {"arg": "None", "command": "quit", "data": "None"},
]


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSMTPServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_smtp_server(server_logs):
    with wait_for_server(PORT):
        client = SMTP(IP, int(PORT))
        client.ehlo()
        client.login(USERNAME, PASSWORD)
        client.sendmail("fromtest", "totest", "Nothing")
        client.quit()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 9
    connect1, connect2, auth, login, *additional = logs
    assert_connect_is_logged(connect1, PORT)
    assert_connect_is_logged(connect2, PORT)
    assert_login_is_logged(login)

    assert auth["data"]["command"] == "AUTH"
    assert b64decode(auth["data"]["data"]).decode() == f"\x00{USERNAME}\x00{PASSWORD}"

    for entry, expected in zip(additional, EXPECTED_DATA):
        assert entry["data"] == expected
