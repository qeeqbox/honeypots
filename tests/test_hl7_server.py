from __future__ import annotations

import pytest
from hl7apy.parser import parse_message, parse_segment

from honeypots import HL7Server
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    wait_for_server,
    connect_to,
)

PORT = "52575"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": HL7Server, "port": PORT}],
    indirect=True,
)
def test_hl7_server(server_logs):
    id_ = 1234

    with wait_for_server(PORT), connect_to(IP, PORT) as connection:
        message = parse_message(
            "\x0bMSH|^~\\&|sending_app|sending_facility|receiving_app|receiving_facility|"
            f"20240214100348||ADT^A01|{id_}|T|2.3\r\x1c\r"
        )
        connection.send(message.to_mllp().encode())
        response = connection.recv(1024).decode()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    assert "ACK" in response
    connect, query = logs
    assert_connect_is_logged(connect, PORT)

    assert "message" in query["data"]
    assert len(query["data"]["message"]) == 1

    response_segments = [parse_segment(s) for s in response[1:].split("\r")[:-2]]
    assert len(response_segments) == 2
    header, ack_segment = response_segments
    # sending app of sent package should equal receiving app of response
    assert header.msh_3.value == message.msh.msh_5.value
    assert ack_segment.name == "MSA"
    assert ack_segment.msa_2.value == str(id_)
