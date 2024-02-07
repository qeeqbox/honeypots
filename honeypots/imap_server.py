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
from random import choice

from twisted import cred
from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.mail.imap4 import (
    IMAP4Server,
    IllegalClientResponse,
    IllegalOperation,
    IllegalMailboxEncoding,
)

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QIMAPServer(BaseServer):
    NAME = "imap_server"
    DEFAULT_PORT = 143

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            [b"OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.6944.0 DC9 ready"]
        )

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomIMAP4Server(IMAP4Server):
            def parse_command(self, line):
                args = line.split(None, 2)
                rest = None
                if len(args) == 3:  # noqa: PLR2004
                    tag, cmd, rest = args
                elif len(args) == 2:  # noqa: PLR2004
                    tag, cmd = args
                elif len(args) == 1:
                    tag = args[0]
                    self.sendBadResponse(tag, "Missing command")
                    return None
                else:
                    self.sendBadResponse(None, "Null command")
                    return None

                cmd = cmd.upper()

                if "capture_commands" in _q_s.options:
                    _q_s.log(
                        {
                            "action": "command",
                            "data": {
                                "cmd": check_bytes(cmd),
                                "tag": check_bytes(tag),
                                "data": check_bytes(rest),
                            },
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                        }
                    )

                try:
                    return self.dispatchCommand(tag, cmd, rest)
                except IllegalClientResponse as e:
                    self.sendBadResponse(tag, "Illegal syntax: " + str(e))
                except IllegalOperation as e:
                    self.sendNegativeResponse(tag, "Illegal operation: " + str(e))
                except IllegalMailboxEncoding as e:
                    self.sendNegativeResponse(tag, "Illegal mailbox name: " + str(e))

            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )
                self.sendPositiveResponse(message=_q_s.mocking_server)

            def authenticateLogin(self, user, passwd):  # noqa: N802
                username = check_bytes(user)
                password = check_bytes(passwd)
                peer = self.transport.getPeer()
                _q_s.check_login(username, password, ip=peer.host, port=peer.port)
                raise cred.error.UnauthorizedLogin()

            def lineReceived(self, line: bytes):  # noqa: N802
                with suppress(IndexError):
                    _line = line.split(b" ")[1].lower()
                    if _line.startswith((b"login", b"capability")):
                        super().lineReceived(line)

        class CustomIMAPFactory(Factory):
            protocol = CustomIMAP4Server
            portal = None

            def buildProtocol(self, _):  # noqa: N802
                protocol = self.protocol()
                protocol.portal = self.portal
                protocol.factory = self
                return protocol

        factory = CustomIMAPFactory()
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from imaplib import IMAP4

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            imap_test = IMAP4(_ip, _port)
            # imap_test.welcome
            imap_test.login(_username, _password)


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qimapserver = QIMAPServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qimapserver.run_server()
