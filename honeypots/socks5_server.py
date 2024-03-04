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
    check_bytes,
)


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
                    v, m = unpack("!BB", self.connection.recv(2))
                    if v == 5:
                        if 2 in unpack("!" + "B" * m, self.connection.recv(m)):
                            self.connection.sendall(b"\x05\x02")
                            if 1 in unpack("B", self.connection.recv(1)):
                                _len = ord(self.connection.recv(1))
                                username = check_bytes(self.connection.recv(_len))
                                _len = ord(self.connection.recv(1))
                                password = check_bytes(self.connection.recv(_len))
                                _q_s.check_login(username, password, src_ip, src_port)
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
