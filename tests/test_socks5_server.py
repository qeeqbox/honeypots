from __future__ import annotations

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
    try:
        requests.get(
            "http://127.0.0.1/",
            proxies={"http": f"socks5://{USERNAME}:{PASSWORD}@{IP}:{PORT}"},
        )
    except requests.exceptions.ConnectionError:
        pass

    sleep(1)  # give the server process some time to write logs

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
