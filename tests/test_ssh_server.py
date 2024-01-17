from __future__ import annotations

from time import sleep

import pytest
from paramiko import AutoAddPolicy, SSHClient

from honeypots import QSSHServer
from .utils import assert_connect_is_logged, IP, load_logs_from_file, PASSWORD, USERNAME

PORT = 50022
SERVER_CONFIG = {
    "honeypots": {
        "ssh": {
            "options": ["capture_commands"],
        },
    }
}


@pytest.mark.parametrize(
    "server_logs",
    [{"server": QSSHServer, "port": str(PORT), "custom_config": SERVER_CONFIG}],
    indirect=True,
)
def test_ssh_server(server_logs):
    sleep(1)  # give the server some time to start

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(IP, port=PORT, username=USERNAME, password=PASSWORD)
    ssh.close()

    sleep(1)  # give the server process some time to write logs

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 2
    connect, login = logs
    assert_connect_is_logged(connect, str(PORT))

    assert login["action"] == "login"
    assert login["username"] == USERNAME
