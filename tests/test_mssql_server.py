from __future__ import annotations

from contextlib import suppress
from time import sleep

import pymssql
import pytest

from honeypots import QMSSQLServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "51433"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QMSSQLServer, "port": PORT}],
    indirect=True,
)
def test_mssql_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(pymssql.OperationalError):
        connection = pymssql.connect(
            host=IP,
            port=str(PORT),
            user=USERNAME,
            password=PASSWORD,
            database="dbname",
        )
        connection.close()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
