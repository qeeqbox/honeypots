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
from __future__ import annotations

from contextlib import suppress

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    check_bytes,
    run_single_server,
)


class QRedisServer(BaseServer):
    NAME = "redis_server"
    DEFAULT_PORT = 6379

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomRedisProtocol(Protocol):
            def get_command(self, data):
                with suppress(Exception):
                    _data = data.decode("utf-8").split("\x0d\x0a")
                    if _data[0][0] == "*":
                        _count = int(_data[0][1]) - 1
                        _data.pop(0)
                        command = self._parse_field(_data, 0)
                        if command:
                            return _count, _data[1::2][0]

                return 0, ""

            def parse_data(self, count: int, data: bytes):
                _data = data.decode("utf-8").split("\r\n")[3::]
                username, password = "", ""
                if count == 2:  # noqa: PLR2004
                    username = self._parse_field(_data, 0)
                    password = self._parse_field(_data, 1)
                elif count == 1:
                    password = self._parse_field(_data, 0)
                if count in {1, 2}:
                    peer = self.transport.getPeer()
                    _q_s.check_login(
                        check_bytes(username), check_bytes(password), ip=peer.host, port=peer.port
                    )

            @staticmethod
            def _parse_field(str_list: list[str], index: int) -> str:
                if str_list[0::2][index][0] == "$" and len(str_list[1::2][index]) == int(
                    str_list[0::2][index][1]
                ):
                    return str_list[1::2][index]
                return ""

            def connectionMade(self):  # noqa: N802
                self._state = 1
                self._variables = {}
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data: bytes):  # noqa: N802
                count, command = self.get_command(data)
                if command == "AUTH":
                    self.parse_data(count, data)
                    self.transport.write(b"-ERR invalid password\r\n")
                else:
                    self.transport.write(f'-ERR unknown command "{command}"\r\n'.encode())
                self.transport.loseConnection()

        factory = Factory()
        factory.protocol = CustomRedisProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from redis import StrictRedis

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            r = StrictRedis.from_url(f"redis://{_username}:{_password}@{_ip}:{_port}/1")
            for _ in r.scan_iter("user:*"):
                pass


if __name__ == "__main__":
    run_single_server(QRedisServer)
