from __future__ import annotations

from smtplib import SMTP
from time import sleep

import pytest
from honeypots import QSMTPServer

from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50025"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSMTPServer, "port": PORT}],
    indirect=True,
)
def test_smtp_server(server_logs):
    sleep(1)  # give server time to start

    client = SMTP(IP, int(PORT))
    client.ehlo()
    client.login(USERNAME, PASSWORD)
    client.sendmail('fromtest', 'totest', 'Nothing')
    client.quit()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
