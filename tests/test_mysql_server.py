from __future__ import annotations

from contextlib import suppress
from time import sleep

import mysql.connector
import pytest

from honeypots import QMysqlServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "53306"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QMysqlServer, "port": PORT}],
    indirect=True,
)
def test_mysql_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(mysql.connector.errors.OperationalError):
        connection = mysql.connector.connect(
            user=USERNAME,
            password=PASSWORD,
            host=IP,
            port=PORT,
            database="test",
            connect_timeout=1000,
        )
        connection.close()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
