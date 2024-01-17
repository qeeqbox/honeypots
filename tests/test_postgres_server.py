from __future__ import annotations

from contextlib import suppress
from time import sleep

import pytest
from psycopg2 import connect, OperationalError

from honeypots import QPostgresServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "55432"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPostgresServer, "port": PORT}],
    indirect=True,
)
def test_postgres_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(OperationalError):
        db = connect(host=IP, port=PORT, user=USERNAME, password=PASSWORD)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect_, login = logs
    assert_connect_is_logged(connect_, PORT)
    assert_login_is_logged(login)
