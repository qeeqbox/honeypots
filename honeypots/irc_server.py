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
    server_arguments,
)


class QIRCServer(BaseServer):
    NAME = "irc_server"
    DEFAULT_PORT = 6667

    def server_main(self):
        _q_s = self

        class CustomIRCProtocol(service.IRCUser):
            def connectionMade(self):
                _q_s.logs.info(
                    {
                        "server": _q_s.NAME,
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                    }
                )

            def handleCommand(self, command, prefix, params):
                if "capture_commands" in _q_s.options:
                    _q_s.logs.info(
                        {
                            "server": _q_s.NAME,
                            "action": "command",
                            "data": {
                                "command": check_bytes(command),
                                "prefix": check_bytes(prefix),
                                "params": check_bytes(params),
                            },
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                            "dest_ip": _q_s.ip,
                            "dest_port": _q_s.port,
                        }
                    )
                service.IRCUser.handleCommand(self, command, prefix, params)

            def dataReceived(self, data: bytes):
                try:
                    service.IRCUser.dataReceived(self, data)
                except UnicodeDecodeError:
                    _q_s.logger.debug(
                        f"[{_q_s.NAME}]: Could not decode data as utf-8: {data.hex(' ')}"
                    )

            def irc_unknown(self, prefix, command, params):
                pass

            def irc_NICK(self, prefix, params):
                status = False
                username = check_bytes("".join(params))
                password = check_bytes(self.password)
                if password == check_bytes(_q_s.password):
                    if username == _q_s.username:
                        status = True
                _q_s.logs.info(
                    {
                        "server": _q_s.NAME,
                        "action": "login",
                        "status": status,
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                        "username": username,
                        "password": password,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                    }
                )

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


def check_bytes(string):
    if isinstance(string, bytes):
        return string.decode(errors="replace")
    else:
        return str(string)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QIRCServer = QIRCServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QIRCServer.run_server()
