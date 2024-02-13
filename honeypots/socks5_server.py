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
import struct
from contextlib import suppress
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from struct import unpack

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QSOCKS5Server(BaseServer):
    NAME = "socks5_server"
    DEFAULT_PORT = 1080

    def server_main(self):
        _q_s = self

        class CustomStreamRequestHandler(StreamRequestHandler):
            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def handle(self):
                src_ip, src_port = self.client_address
                _q_s.logs.info(
                    {
                        "server": _q_s.NAME,
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                    }
                )
                try:
                    v, m = unpack("!BB", self.connection.recv(2))
                    if v == 5:
                        if 2 in unpack("!" + "B" * m, self.connection.recv(m)):
                            self.connection.sendall(b"\x05\x02")
                            if 1 in unpack("B", self.connection.recv(1)):
                                _len = ord(self.connection.recv(1))
                                username = self.connection.recv(_len)
                                _len = ord(self.connection.recv(1))
                                password = self.connection.recv(_len)
                                username = self.check_bytes(username)
                                password = self.check_bytes(password)
                                status = "failed"
                                if username == _q_s.username and password == _q_s.password:
                                    status = "success"
                                _q_s.logs.info(
                                    {
                                        "server": _q_s.NAME,
                                        "action": "login",
                                        "status": status,
                                        "src_ip": src_ip,
                                        "src_port": src_port,
                                        "dest_ip": _q_s.ip,
                                        "dest_port": _q_s.port,
                                        "username": username,
                                        "password": password,
                                    }
                                )
                except ConnectionResetError:
                    _q_s.logger.debug(
                        f"[{_q_s.NAME}]: Connection reset error when trying to handle connection"
                    )
                except struct.error:
                    _q_s.logger.debug(f"[{_q_s.NAME}]: Could not parse data to handle connection")

                self.server.close_request(self.request)

        class ThreadingTCPServer(ThreadingMixIn, TCPServer):
            pass

        TCPServer.allow_reuse_address = True
        server = ThreadingTCPServer((self.ip, self.port), CustomStreamRequestHandler)
        server.serve_forever()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get(
                "https://yahoo.com",
                proxies=dict(
                    http=f"socks5://{_username}:{_password}@{_ip}:{_port}",
                    https=f"socks5://{_username}:{_password}@{_ip}:{_port}",
                ),
            )


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSOCKS5Server = QSOCKS5Server(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QSOCKS5Server.run_server()
