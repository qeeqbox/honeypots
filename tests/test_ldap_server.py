from __future__ import annotations

from contextlib import suppress
from time import sleep

import pytest
from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult

from honeypots import QLDAPServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50389"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QLDAPServer, "port": PORT}],
    indirect=True,
)
def test_ldap_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(LDAPInsufficientAccessRightsResult):
        connection = Connection(
            Server(IP, port=int(PORT), get_info=ALL),
            authentication="SIMPLE",
            user=USERNAME,
            password=PASSWORD,
            check_names=True,
            lazy=False,
            client_strategy="SYNC",
            raise_exceptions=True,
        )
        connection.open()
        connection.bind()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
