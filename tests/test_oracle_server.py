from __future__ import annotations

from time import sleep

import pytest

from honeypots import QOracleServer
from .utils import (
    assert_connect_is_logged,
    connect_to,
    IP,
    load_logs_from_file,
    USERNAME,
)

PORT = "51521"
PROGRAM = "foo"
SERVICE = "bar"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QOracleServer, "port": PORT}],
    indirect=True,
)
def test_oracle_server(server_logs):
    sleep(1)  # give the server some time to start

    payload = (
        "\x00\x00\x03\x04\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x01F\xb9\xd9@\x00@\x06\x81\xd6"
        "\x7f\x00\x00\x01\x7f\x00\x00\x01\xbf\xce\x06\x13\xacW\xde\xc0Z\xb5\x0cI\x80\x18\x02\x00\xff:\x00\x00"
        "\x01\x01\x08\n\x1bdZ^\x1bdZ^\x01\x12\x00\x00\x01\x00\x00\x00\x01>\x01,\x0cA \x00\xff\xff\x7f\x08\x00"
        "\x00\x01\x00\x00\xc8\x00J\x00\x00\x14\x00AA\xa7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        f"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={SERVICE})(CID=(PROGRAM={PROGRAM})(HOST=xxxxxxxxxxxxxx)"
        f"(USER={USERNAME}))(CONNECTION_ID=xxxxxxxxxxxxxxxxxxxxxxxx))(ADDRESS=(PROTOCOL=tcp)(HOST={IP})(PORT={PORT})))"
    )
    with connect_to(IP, PORT) as connection:
        connection.send(payload.encode())
        response, _ = connection.recvfrom(10000)

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, PORT)

    assert login["action"] == "login"
    assert login["data"] == {"local_user": USERNAME, "program": PROGRAM, "service_name": SERVICE}

    assert response == b"\x00\x08\x00\x00\x04\x00\x00\x00"
