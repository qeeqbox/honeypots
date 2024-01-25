from __future__ import annotations

from contextlib import suppress

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
    wait_for_server,
)

PORT = "55432"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QPostgresServer, "port": PORT}],
    indirect=True,
)
def test_postgres_server(server_logs):
    with wait_for_server(PORT), suppress(OperationalError):
        connect(host=IP, port=PORT, user=USERNAME, password=PASSWORD)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect_, login = logs
    assert_connect_is_logged(connect_, PORT)
    assert_login_is_logged(login)
