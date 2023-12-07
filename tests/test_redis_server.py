from __future__ import annotations

from contextlib import suppress
from time import sleep

import pytest
from honeypots import QRedisServer
from redis import AuthenticationError, StrictRedis

from .utils import (
    assert_connect_is_logged,
    assert_login_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
)

PORT = "56379"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QRedisServer, "port": PORT}],
    indirect=True,
)
def test_redis_server(server_logs):
    with suppress(AuthenticationError):
        redis = StrictRedis.from_url(f"redis://{USERNAME}:{PASSWORD}@{IP}:{PORT}/1")
        for _ in redis.scan_iter("user:*"):
            pass

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)
    assert_login_is_logged(login)
