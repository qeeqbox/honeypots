from __future__ import annotations

from time import sleep

import pytest
import requests

from honeypots import QHTTPServer

from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "50080"
SERVER_CONFIG = {
    "honeypots": {
        "http": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QHTTPServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_http_server(server_logs):
    sleep(1)  # give the server some time to start

    url = f"http://{IP}:{PORT}"
    data = {'username': USERNAME, 'password': PASSWORD}
    requests.post(f"{url}/login.html", verify=False, data=data)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    connect, post, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert "data" in connect
    assert connect["data"]["uri"] == "/login.html"
    assert connect["data"]["method"] == "POST"

    assert post["action"] == "POST"
