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

from twisted.conch.telnet import TelnetProtocol, TelnetTransport
from twisted.internet import reactor
from twisted.internet.protocol import Factory

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QTelnetServer(BaseServer):
    NAME = "telnet_server"
    DEFAULT_PORT = 23

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.random_servers = [
            "Ubuntu 18.04 LTS",
            "Ubuntu 16.04.3 LTS",
            "Welcome to Microsoft Telnet Server.",
        ]

    def server_main(self):
        _q_s = self

        class CustomTelnetProtocol(TelnetProtocol):
            _state = None
            _user = None
            _pass = None

            def connectionMade(self):  # noqa: N802
                self._state = None
                self._user = None
                self._pass = None
                self.transport.write(b"PC login: ")
                self._state = b"Username"
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):  # noqa: N802
                data = data.strip()
                if self._state == b"Username":
                    self._user = data
                    self._state = b"Password"
                    self.transport.write(b"Password: ")
                elif self._state == b"Password":
                    username = check_bytes(self._user)
                    password = check_bytes(data)
                    peer = self.transport.getPeer()
                    _q_s.check_login(username, password, ip=peer.host, port=peer.port)
                    self.transport.loseConnection()
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason=None):  # noqa: N802,ARG002
                self._state = None
                self._user = None
                self._pass = None

        factory = Factory()
        factory.protocol = lambda: TelnetTransport(CustomTelnetProtocol)
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from telnetlib import Telnet as TTelnet

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            _username = _username.encode("utf-8")
            _password = _password.encode("utf-8")
            t = TTelnet(_ip, _port)
            t.read_until(b"login: ")
            t.write(_username + b"\n")
            t.read_until(b"Password: ")
            t.write(_password + b"\n")


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qtelnetserver = QTelnetServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qtelnetserver.run_server()
