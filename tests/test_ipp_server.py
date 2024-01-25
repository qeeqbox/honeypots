from __future__ import annotations

import pytest
import requests

from honeypots import QIPPServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    wait_for_server,
)

PORT = "50631"
SERVER_CONFIG = {
    "honeypots": {
        "ipp": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QIPPServer, "port": PORT, "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_ipp_server(server_logs):
    with wait_for_server(PORT):
        body = (
            b"\x02\x00\x00\x0b\x00\x01/p\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1b"
            b"attributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x00\x15"
            b"ipp://127.0.0.1:631/D\x00\x14requested-attributes\x00\x03allD\x00\x00\x00\x12media-col-database\x03"
        )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": f"{len(body)}",
            "Host": f"{IP}:{PORT}",
            "Connection": "close",
        }
        requests.post(f"http://{IP}:{PORT}/", data=body, headers=headers)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, query = logs
    assert_connect_is_logged(connect, PORT)

    assert query["action"] == "query"
    assert query["data"] == {
        "request": (
            "VERSION 2.0|REQUEST 0x12f70|OPERATION Get-Printer-Attributes|GROUP "
            "operation-attributes-tag|ATTR attributes-charset utf-8|ATTR "
            "attributes-natural-language en|ATTR printer-uri ipp://127.0.0.1:631/D"
        )
    }
