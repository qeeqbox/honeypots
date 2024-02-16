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
from twisted.internet.protocol import Factory
from twisted.words import service

from honeypots.base_server import BaseServer
from honeypots.helper import (
    check_bytes,
    run_single_server,
)


class QIRCServer(BaseServer):
    NAME = "irc_server"
    DEFAULT_PORT = 6667

    def server_main(self):
        _q_s = self

        class CustomIRCProtocol(service.IRCUser):
            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def handleCommand(self, command, prefix, params):  # noqa: N802
                if "capture_commands" in _q_s.options:
                    _q_s.log(
                        {
                            "action": "command",
                            "data": {
                                "command": check_bytes(command),
                                "prefix": check_bytes(prefix),
                                "params": check_bytes(params),
                            },
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                        }
                    )
                service.IRCUser.handleCommand(self, command, prefix, params)

            def dataReceived(self, data: bytes):  # noqa: N802
                try:
                    service.IRCUser.dataReceived(self, data)
                except UnicodeDecodeError:
                    _q_s.logger.debug(
                        f"[{_q_s.NAME}]: Could not decode data as utf-8: {data.hex(' ')}"
                    )

            def irc_unknown(self, prefix, command, params):
                pass

            def irc_NICK(self, prefix, params):  # noqa: N802,ARG002
                username = check_bytes("".join(params))
                password = check_bytes(self.password)
                peer = self.transport.getPeer()
                _q_s.check_login(username, password, ip=peer.host, port=peer.port)

        factory = Factory()
        factory.protocol = CustomIRCProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings

            filterwarnings(action="ignore", module=".*socket.*")
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            c = socket(AF_INET, SOCK_STREAM)
            c.connect((_ip, _port))
            c.setblocking(False)
            c.send(f"PASS {_password}\n".encode())
            c.close()


if __name__ == "__main__":
    run_single_server(QIRCServer)
