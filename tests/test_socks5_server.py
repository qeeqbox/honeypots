from __future__ import annotations

from contextlib import suppress
from time import sleep

import pytest
import requests

from honeypots import QSOCKS5Server
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "51080"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSOCKS5Server, "port": PORT}],
    indirect=True,
)
def test_socks5_server(server_logs):
    with suppress(requests.exceptions.ConnectionError):
        requests.get(
            "http://127.0.0.1/",
            proxies={"http": f"socks5://{USERNAME}:{PASSWORD}@{IP}:{PORT}"},
        )

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
