from __future__ import annotations

import pytest
from paramiko import AutoAddPolicy, SSHClient

from honeypots import QSSHServer
from .utils import (
    assert_connect_is_logged,
    IP,
    load_logs_from_file,
    PASSWORD,
    USERNAME,
    wait_for_server,
)

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
    with wait_for_server(PORT):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(IP, port=PORT, username=USERNAME, password=PASSWORD)
        ssh.exec_command("ls")
        ssh.close()

    logs = load_logs_from_file(server_logs)

    assert len(logs) == 3
    connect, login, command = logs
    assert_connect_is_logged(connect, str(PORT))

    assert command["action"] == "command"
    assert command["data"] == {"command": "ls"}
    assert login["action"] == "login"
    assert login["username"] == USERNAME
