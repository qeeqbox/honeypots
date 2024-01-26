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

from _thread import start_new_thread
from binascii import hexlify
from contextlib import suppress
from io import StringIO
from random import choice
from re import compile as rcompile
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Event
from time import time

from paramiko import (
    RSAKey,
    ServerInterface,
    Transport,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
    AUTH_FAILED,
)
from paramiko.ssh_exception import SSHException

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QSSHServer(BaseServer):
    NAME = "ssh_server"
    DEFAULT_PORT = 22

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            ["OpenSSH 7.5", "OpenSSH 7.3", "Serv-U SSH Server 15.1.1.108", "OpenSSH 6.4"]
        )
        self.ansi = rcompile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")

    def generate_pub_pri_keys(self):
        with suppress(Exception):
            key = RSAKey.generate(2048)
            string_io = StringIO()
            key.write_private_key(string_io)
            return key.get_base64(), string_io.getvalue()
        return None, None

    def server_main(self):
        _q_s = self

        class SSHHandle(ServerInterface):
            def __init__(self, ip, port):
                self.ip = ip
                self.port = port
                self.event = Event()
                # ServerInterface.__init__(self)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def check_channel_request(self, kind, chanid):
                if kind == "session":
                    return OPEN_SUCCEEDED
                return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_auth_password(self, username, password):
                username = self.check_bytes(username)
                password = self.check_bytes(password)
                status = "failed"
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = "success"
                if status == "success":
                    _q_s.logs.info(
                        {
                            "server": "ssh_server",
                            "action": "login",
                            "status": status,
                            "src_ip": self.ip,
                            "src_port": self.port,
                            "dest_ip": _q_s.ip,
                            "dest_port": _q_s.port,
                            "username": username,
                            "password": password,
                        }
                    )
                    return AUTH_SUCCESSFUL
                _q_s.logs.info(
                    {
                        "server": "ssh_server",
                        "action": "login",
                        "status": status,
                        "src_ip": self.ip,
                        "src_port": self.port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                        "username": username,
                        "password": password,
                    }
                )
                return AUTH_FAILED

            def check_channel_exec_request(self, channel, command):
                if "capture_commands" in _q_s.options:
                    _q_s.logs.info(
                        {
                            "server": "ssh_server",
                            "action": "command",
                            "src_ip": self.ip,
                            "src_port": self.port,
                            "dest_ip": _q_s.ip,
                            "dest_port": _q_s.port,
                            "data": {"command": self.check_bytes(command)},
                        }
                    )
                self.event.set()
                return True

            def get_allowed_auths(self, username):
                return "password,publickey"

            def check_auth_publickey(self, username, key):
                _q_s.logs.info(
                    {
                        "server": "ssh_server",
                        "action": "login",
                        "src_ip": self.ip,
                        "src_port": self.port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                        "username": self.check_bytes(username),
                        "key_fingerprint": self.check_bytes(hexlify(key.get_fingerprint())),
                    }
                )
                return AUTH_SUCCESSFUL

            def check_channel_shell_request(self, channel):
                return True

            def check_channel_direct_tcpip_request(self, chanid, origin, destination):
                return OPEN_SUCCEEDED

            def check_channel_pty_request(
                self, channel, term, width, height, pixelwidth, pixelheight, modes
            ):
                return True

        def ConnectionHandle(client, priv):
            with suppress(Exception):
                t = Transport(client)
                ip, port = client.getpeername()
                _q_s.logs.info(
                    {
                        "server": "ssh_server",
                        "action": "connection",
                        "src_ip": ip,
                        "src_port": port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                    }
                )
                t.local_version = "SSH-2.0-" + _q_s.mocking_server
                t.add_server_key(RSAKey(file_obj=StringIO(priv)))
                sshhandle = SSHHandle(ip, port)
                try:
                    t.start_server(server=sshhandle)
                except SSHException:
                    return
                conn = t.accept(30)
                if "interactive" in _q_s.options and conn is not None:
                    conn.send(
                        b"Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.10.60.1-microsoft-standard-WSL2 x86_64)\r\n\r\n"
                    )
                    current_time = time()
                    while True and time() < current_time + 10:
                        conn.send(b"/$ ")
                        line = ""
                        while (
                            not line.endswith("\x0d")
                            and not line.endswith("\x0a")
                            and time() < current_time + 10
                        ):
                            conn.settimeout(10)
                            recv = conn.recv(1).decode()
                            conn.settimeout(None)
                            if _q_s.ansi.match(recv) is None and recv != "\x7f":
                                conn.send(recv.encode())
                                line += recv
                        line = line.rstrip()
                        _q_s.logs.info(
                            {
                                "server": "ssh_server",
                                "action": "interactive",
                                "src_ip": ip,
                                "src_port": port,
                                "dest_ip": _q_s.ip,
                                "dest_port": _q_s.port,
                                "data": {"command": line},
                            }
                        )
                        if line == "ls":
                            conn.send(
                                b"\r\nbin cdrom etc lib lib64 lost+found mnt proc run snap "
                                b"swapfile tmp var boot dev home lib32 libx32 media opt root "
                                b"sbin srv sys usr\r\n"
                            )
                        elif line == "pwd":
                            conn.send(b"\r\n/\r\n")
                        elif line == "whoami":
                            conn.send(b"\r\nroot\r\n")
                        elif line == "exit":
                            break
                        else:
                            conn.send(f"\r\n{line}: command not found\r\n".encode())
                with suppress(Exception):
                    sshhandle.event.wait(2)
                with suppress(Exception):
                    conn.close()
                with suppress(Exception):
                    t.close()

        sock = socket(AF_INET, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(1)
        pub, priv = self.generate_pub_pri_keys()
        while True:
            with suppress(Exception):
                client, addr = sock.accept()
                start_new_thread(
                    ConnectionHandle,
                    (
                        client,
                        priv,
                    ),
                )

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
