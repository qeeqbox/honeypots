from __future__ import annotations

from contextlib import suppress
from time import sleep

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
)

PORT = "59200"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QElasticServer, "port": PORT}],
    indirect=True,
)
def test_elastic_server(server_logs):
    sleep(1)  # give the server some time to start

    with suppress(NotFoundError):
        elastic = Elasticsearch(
            [f"https://{IP}:{PORT}"],
            basic_auth=(USERNAME, PASSWORD),
            verify_certs=False,
        )
        elastic.search(index="test", body={}, size=99)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
