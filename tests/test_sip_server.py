from __future__ import annotations

from _socket import IPPROTO_UDP
from socket import AF_INET, SOCK_DGRAM, socket
from time import sleep

import pytest
from honeypots import QSIPServer

from .utils import IP, load_logs_from_file

PORT = "55060"
EXPECTED_KEYS = ("action", "server", "src_ip", "src_port", "timestamp")
CALL_ID = "1@0.0.0.0"
CONTACT = "sip:user_3@test.test.test"
FROM = f"{CONTACT};tag=none"
TO = "<sip:user_2@test.test>"


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSIPServer, "port": PORT}],
    indirect=True,
)
def test_sip_server(server_logs):
    sleep(1)  # give the server some time to start

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    sock.sendto(
        "INVITE sip:user_1@test.test SIP/2.0\r\n"
        f"To: {TO}\r\n"
        f"From: {FROM}\r\n"
        f"Call-ID: {CALL_ID}\r\n"
        "CSeq: 1 INVITE\r\n"
        f"Contact: {CONTACT}\r\n"
        "Via: SIP/2.0/TCP 0.0.0.0;branch=34uiddhjczqw3mq23\r\n"
        "Content-Length: 1\r\n\r\nT".encode(),
        (IP, int(PORT)),
    )
    sock.close()

    sleep(1)  # give the server process some time to write logs

    log_files = [f for f in server_logs.iterdir()]
    assert len(log_files) == 1
    logs = load_logs_from_file(log_files[0])

    assert len(logs) == 2
    connect, request = logs

    assert all(k in connect for k in EXPECTED_KEYS)
    assert connect["action"] == "connection"
    assert connect["server"] == "sip_server"

    assert request["action"] == "request"
    assert request["src_ip"] == IP
    assert "data" in request
    assert request["data"]["call-id"] == CALL_ID
    assert request["data"]["contact"] == CONTACT
    assert request["data"]["from"] == FROM
    assert request["data"]["to"] == TO
