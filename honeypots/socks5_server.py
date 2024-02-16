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
    check_bytes,
    run_single_server,
)

USER_PW_AUTH_V1 = 1
SOCKS_V5 = 5
AUTH_TYPE_USER_PW = 2


class QSOCKS5Server(BaseServer):
    NAME = "socks5_server"
    DEFAULT_PORT = 1080

    def server_main(self):
        _q_s = self

        class CustomStreamRequestHandler(StreamRequestHandler):
            def handle(self):
                src_ip, src_port = self.client_address
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                    }
                )
                try:
                    # see RFC 1928
                    version, auth_types_len = unpack("!BB", self.connection.recv(2))
                    if version == SOCKS_V5:
                        supported_auth_methods = unpack(
                            "!" + "B" * auth_types_len, self.connection.recv(auth_types_len)
                        )
                        if AUTH_TYPE_USER_PW in supported_auth_methods:
                            self.connection.sendall(b"\x05\x02")
                            self._check_user_pw_auth(src_ip, src_port)
                except ConnectionResetError:
                    _q_s.logger.debug(
                        f"[{_q_s.NAME}]: Connection reset error when trying to handle connection"
                    )
                except struct.error:
                    _q_s.logger.debug(f"[{_q_s.NAME}]: Could not parse data to handle connection")

                self.server.close_request(self.request)

            def _check_user_pw_auth(self, ip: str, port: int):
                # see RFC 1929
                auth_version = unpack("B", self.connection.recv(1))[0]
                if auth_version == USER_PW_AUTH_V1:
                    _len = ord(self.connection.recv(1))
                    username = check_bytes(self.connection.recv(_len))
                    _len = ord(self.connection.recv(1))
                    password = check_bytes(self.connection.recv(_len))
                    _q_s.check_login(username, password, ip, port)

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
                proxies={
                    "http": f"socks5://{_username}:{_password}@{_ip}:{_port}",
                    "https": f"socks5://{_username}:{_password}@{_ip}:{_port}",
                },
            )


if __name__ == "__main__":
    run_single_server(QSOCKS5Server)
