from __future__ import annotations

from contextlib import suppress

import pytest
from elasticsearch import Elasticsearch, NotFoundError

from honeypots import QElasticServer
from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

PORT = "59200"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QElasticServer, "port": PORT}],
    indirect=True,
)
def test_elastic_server(server_logs):
    with wait_for_server(PORT), suppress(NotFoundError):
        elastic = Elasticsearch(
            [f"https://{IP}:{PORT}"],
            basic_auth=(USERNAME, PASSWORD),
            verify_certs=False,
        )
        elastic.search(index="test", body={}, size=99)

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    connect, login, dump = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)

    assert "headers" in dump
    assert dump["data"] == "POST /test/_search HTTP/1.1\r\n"
