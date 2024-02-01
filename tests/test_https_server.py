from __future__ import annotations

import pytest
import requests

from honeypots import QHTTPSServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = "50443"
SERVER_CONFIG = {
    "honeypots": {
        "https": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QHTTPSServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_https_server(server_logs):
    with wait_for_server(PORT):
        url = f"https://{IP}:{PORT}"
        data = {"username": USERNAME, "password": PASSWORD}
        requests.post(f"{url}/login.html", verify=False, data=data)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    connect, post, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert "data" in connect
    assert connect["data"]["uri"] == "/login.html"
    assert connect["data"]["method"] == "POST"

    assert post["action"] == "POST"
