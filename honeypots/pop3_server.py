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
from twisted.internet.protocol import Factory
from twisted.mail.pop3 import POP3, POP3Error

from honeypots.base_server import BaseServer
from honeypots.helper import check_bytes, server_arguments


class QPOP3Server(BaseServer):
    NAME = "pop3_server"
    DEFAULT_PORT = 110

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = "Microsoft Exchange POP3 service is ready"

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomPOP3Protocol(POP3):
            self._user = None

            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )
                self._user = None
                self.successResponse(_q_s.mocking_server)

            def processCommand(self, command: bytes, *args):  # noqa: N802
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.log(
                            {
                                "action": "command",
                                "data": {
                                    "cmd": check_bytes(command),
                                    "args": check_bytes(b" ".join(args)),
                                },
                                "src_ip": self.transport.getPeer().host,
                                "src_port": self.transport.getPeer().port,
                            }
                        )

                if not (
                    command.lower().startswith(b"user") or command.lower().startswith(b"pass")
                ):
                    self.failResponse("Authentication failed")
                    return None

                if self.blocked is not None:
                    self.blocked.append((command, args))
                    return None

                command = command.upper()
                if not self.mbox and command not in self.AUTH_CMDS:
                    raise POP3Error(b"not authenticated yet: cannot do " + command)
                f = getattr(self, f"do_{check_bytes(command)}", None)
                if f:
                    return f(*args)
                raise POP3Error(b"Unknown protocol command: " + command)

            def do_USER(self, user):  # noqa: N802
                self._user = user
                self.successResponse("USER Ok")

            def do_PASS(self, password: bytes, *words: tuple[bytes]):  # noqa: N802
                if self._user:
                    username = check_bytes(self._user)
                    password = check_bytes(b" ".join((password, *words)))
                    peer = self.transport.getPeer()
                    _q_s.check_login(username, password, ip=peer.host, port=peer.port)
                    self.failResponse("Authentication failed")
                else:
                    self.failResponse("USER first, then PASS")

                self._user = None

        class CustomPOP3Factory(Factory):
            protocol = CustomPOP3Protocol
            portal = None

            def buildProtocol(self, address):  # noqa: N802,ARG002
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        factory = CustomPOP3Factory()
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from poplib import POP3 as POP3Client  # noqa: N811

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            pp = POP3Client(_ip, _port)
            pp.user(_username)
            pp.pass_(_password)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qpop3server = QPOP3Server(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qpop3server.run_server()
