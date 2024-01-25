from __future__ import annotations

from contextlib import suppress

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
    wait_for_server,
)

PORT = "51433"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QMSSQLServer, "port": PORT}],
    indirect=True,
)
def test_mssql_server(server_logs):
    with wait_for_server(PORT), suppress(pymssql.OperationalError):
        connection = pymssql.connect(
            host=IP,
            port=str(PORT),
            user=USERNAME,
            password=PASSWORD,
            database="dbname",
        )
        connection.close()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
