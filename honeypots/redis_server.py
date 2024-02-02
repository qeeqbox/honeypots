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

from contextlib import suppress

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QRedisServer(BaseServer):
    NAME = "redis_server"
    DEFAULT_PORT = 6379

    def server_main(self):
        _q_s = self

        class CustomRedisProtocol(Protocol):
            def get_command(self, data):
                with suppress(Exception):
                    _data = data.decode("utf-8").split("\x0d\x0a")
                    if _data[0][0] == "*":
                        _count = int(_data[0][1]) - 1
                        _data.pop(0)
                        if _data[0::2][0][0] == "$" and len(_data[1::2][0]) == int(
                            _data[0::2][0][1]
                        ):
                            return _count, _data[1::2][0]

                return 0, ""

            def parse_data(self, c, data):
                _data = data.decode("utf-8").split("\r\n")[3::]
                username, password = "", ""
                if c == 2:
                    _ = 0
                    if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
                        username = _data[1::2][_]
                    _ = 1
                    if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
                        password = _data[1::2][_]
                if c == 1:
                    _ = 0
                    if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
                        password = _data[1::2][_]
                if c == 2 or c == 1:
                    peer = self.transport.getPeer()
                    _q_s.check_login(
                        check_bytes(username), check_bytes(password), ip=peer.host, port=peer.port
                    )

            def connectionMade(self):
                self._state = 1
                self._variables = {}
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):
                c, command = self.get_command(data)
                if command == "AUTH":
                    self.parse_data(c, data)
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
            for key in r.scan_iter("user:*"):
                pass


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qredisserver = QRedisServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qredisserver.run_server()
