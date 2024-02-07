"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
"""
import logging
from _thread import start_new_thread
from binascii import hexlify
from contextlib import suppress
from datetime import datetime
from io import StringIO
from random import choice
import re
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Event
from time import time

from paramiko import (
    RSAKey,
    ServerInterface,
    Transport,
)
from paramiko.common import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)
from paramiko.ssh_exception import SSHException

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)

# deactivate logging output of paramiko
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

COMMANDS = {
    "ls": (
        "bin boot cdrom dev etc home lib lib32 libx32 lib64 lost+found media mnt opt proc root "
        "run sbin snap srv sys tmp usr var"
    ),
    "pwd": "/",
    "whoami": "root",
    "": "",
    "cd": "",
    "cd /": "",
    "uname": "Linux",
    "uname -s": "Linux",
    "uname -n": "n1-v26",
    "uname -r": "5.4.0-26-generic",
    "uname -v": "#26-Ubuntu SMP %TIME",
    "uname -m": "x86_64",
    "uname -p": "x86_64",
    "uname -i": "x86_64",
    "uname -o": "GNU/Linux",
    "uname -a": (
        "Linux n1-v26 5.4.0-26-generic #26-Ubuntu SMP %TIME x86_64 x86_64 x86_64 GNU/Linux"
    ),
}


class QSSHServer(BaseServer):
    NAME = "ssh_server"
    DEFAULT_PORT = 22

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            ["OpenSSH 7.5", "OpenSSH 7.3", "Serv-U SSH Server 15.1.1.108", "OpenSSH 6.4"]
        )
        self.ansi = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")

    def generate_pub_pri_keys(self):
        with suppress(Exception):
            key = RSAKey.generate(2048)
            string_io = StringIO()
            key.write_private_key(string_io)
            return key.get_base64(), string_io.getvalue()
        return None, None

    def server_main(self):  # noqa: C901,PLR0915
        _q_s = self

        class SSHHandle(ServerInterface):
            def __init__(self, ip, port):
                self.ip = ip
                self.port = port
                self.event = Event()

            def check_channel_request(self, kind, *_, **__):
                if kind == "session":
                    return OPEN_SUCCEEDED
                return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_auth_password(self, username, password):
                username = check_bytes(username)
                password = check_bytes(password)
                if _q_s.check_login(username, password, self.ip, self.port):
                    return AUTH_SUCCESSFUL
                return AUTH_FAILED

            def check_channel_exec_request(self, channel, command):  # noqa: ARG002
                if "capture_commands" in _q_s.options:
                    _q_s.log(
                        {
                            "action": "command",
                            "src_ip": self.ip,
                            "src_port": self.port,
                            "data": {"command": check_bytes(command)},
                        }
                    )
                self.event.set()
                return True

            def get_allowed_auths(self, *_, **__):
                return "password,publickey"

            def check_auth_publickey(self, username, key):
                _q_s.log(
                    {
                        "action": "login",
                        "src_ip": self.ip,
                        "src_port": self.port,
                        "username": check_bytes(username),
                        "key_fingerprint": check_bytes(hexlify(key.get_fingerprint())),
                    }
                )
                return AUTH_SUCCESSFUL

            def check_channel_shell_request(self, *_, **__):
                return True

            def check_channel_direct_tcpip_request(self, *_, **__):
                return OPEN_SUCCEEDED

            def check_channel_pty_request(self, *_, **__):
                return True

        def handle_connection(client, priv):
            t = Transport(client)
            try:
                ip, port = client.getpeername()
            except OSError as err:
                _q_s.logger.debug(f"Server error: {err}")
                return
            _q_s.log(
                {
                    "action": "connection",
                    "src_ip": ip,
                    "src_port": port,
                }
            )
            t.local_version = "SSH-2.0-" + _q_s.mocking_server
            t.add_server_key(RSAKey(file_obj=StringIO(priv)))
            ssh_handle = SSHHandle(ip, port)
            try:
                t.start_server(server=ssh_handle)
            except (SSHException, EOFError, ConnectionResetError) as err:
                _q_s.logger.warning(f"Server error: {err}")
                return
            conn = t.accept(30)
            if "interactive" in _q_s.options and conn is not None:
                _handle_interactive_session(conn, ip, port)
            with suppress(TimeoutError):
                ssh_handle.event.wait(2)
            with suppress(Exception):
                conn.close()
            with suppress(Exception):
                t.close()

        def _handle_interactive_session(conn, ip, port):
            conn.send(b"Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)\r\n\r\n")
            timeout = time() + 300
            while time() < timeout:
                try:
                    conn.send(b"$ ")
                    line = ""
                    while not line.endswith("\x0d") and not line.endswith("\x0a"):
                        # timeout if the user does not send anything for 10 seconds
                        conn.settimeout(10)
                        recv = conn.recv(1).decode()
                        if not recv:
                            raise EOFError
                        if _q_s.ansi.match(recv) is None and recv != "\x7f":
                            line += recv
                except (TimeoutError, EOFError):
                    break
                line = line.strip()
                _q_s.log(
                    {
                        "action": "interactive",
                        "src_ip": ip,
                        "src_port": port,
                        "data": {"command": line},
                    }
                )
                if line in COMMANDS:
                    response = COMMANDS.get(line)
                    if "%TIME" in response:
                        response = response.replace(
                            "%TIME", datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
                        )
                    conn.send(f"{response}\r\n".encode())
                elif line.startswith("cd "):
                    _, target, *_ = line.split(" ")
                    conn.send(f"sh: 1: cd: can't cd to {target}\r\n".encode())
                elif line == "exit":
                    break
                else:
                    conn.send(f"{line}: command not found\r\n".encode())

        sock = socket(AF_INET, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(1)
        _, private_key = self.generate_pub_pri_keys()
        while True:
            with suppress(Exception):
                client, _ = sock.accept()
                start_new_thread(handle_connection, (client, private_key))

    def test_server(self, ip=None, port=None, username=None, password=None):
        from paramiko import SSHClient, AutoAddPolicy

        _ip = ip or self.ip
        _port = port or self.port
        _username = username or self.username
        _password = password or self.password
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(
            AutoAddPolicy()
        )  # if you have default ones, remove them before using this..
        ssh.connect(_ip, port=_port, username=_username, password=_password)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsshserver = QSSHServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qsshserver.run_server()
