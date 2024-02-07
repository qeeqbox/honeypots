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
from tempfile import TemporaryDirectory

from twisted.cred import portal, credentials
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.cred.portal import Portal
from twisted.internet import reactor, defer
from twisted.protocols.ftp import (
    FTPAnonymousShell,
    FTPFactory,
    FTP,
    IFTPShell,
    GUEST_LOGGED_IN_PROCEED,
    AuthorizationError,
    USR_LOGGED_IN_PROCEED,
)
from twisted.python import filepath
from zope.interface import implementer

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QFTPServer(BaseServer):
    NAME = "ftp_server"
    DEFAULT_PORT = 21

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            [
                "ProFTPD 1.2.10",
                "ProFTPD 1.3.4a",
                "FileZilla ftp 0.9.43",
                "Gene6 ftpd 3.10.0",
                "FileZilla ftp 0.9.33",
                "ProFTPD 1.2.8",
            ]
        )
        self.temp_folder = TemporaryDirectory()

    def server_main(self):  # noqa: C901
        _q_s = self

        @implementer(portal.IRealm)
        class CustomFTPRealm:
            def __init__(self, anonymousRoot):  # noqa: N803
                self.anonymousRoot = filepath.FilePath(anonymousRoot)

            def requestAvatar(  # noqa: N802
                self,
                avatarId,  # noqa: ARG002,N803
                mind,  # noqa: ARG002
                *interfaces,
            ):
                for iface in interfaces:
                    if iface is IFTPShell:
                        avatar = FTPAnonymousShell(self.anonymousRoot)
                        return (
                            IFTPShell,
                            avatar,
                            getattr(avatar, "logout", lambda: None),
                        )
                raise NotImplementedError("Only IFTPShell interface is supported by this realm")

        @implementer(ICredentialsChecker)
        class CustomAccess:
            credentialInterfaces = (  # noqa: N815
                credentials.IAnonymous,
                credentials.IUsernamePassword,
            )

            def requestAvatarId(self, credentials):  # noqa: N802
                with suppress(Exception):
                    username = check_bytes(credentials.username)
                    password = check_bytes(credentials.password)
                    if username == _q_s.username and password == _q_s.password:
                        return defer.succeed(credentials.username)
                return defer.fail(UnauthorizedLogin())

        class CustomFTPProtocol(FTP):
            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )
                self.state = self.UNAUTH
                self.setTimeout(self.timeOut)
                self.reply("220.2", self.factory.welcomeMessage)

            def processCommand(self, cmd, *params):  # noqa: N802
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.log(
                            {
                                "action": "command",
                                "data": {
                                    "cmd": check_bytes(cmd.upper()),
                                    "args": check_bytes(params),
                                },
                                "src_ip": self.transport.getPeer().host,
                                "src_port": self.transport.getPeer().port,
                            }
                        )
                return super().processCommand(cmd, *params)

            def ftp_PASS(self, password):  # noqa: N802
                username = check_bytes(self._user)
                password = check_bytes(password)
                peer = self.transport.getPeer()
                _q_s.check_login(username, password, ip=peer.host, port=peer.port)

                if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
                    creds = credentials.Anonymous()
                    reply = GUEST_LOGGED_IN_PROCEED
                else:
                    creds = credentials.UsernamePassword(self._user, password)
                    reply = USR_LOGGED_IN_PROCEED

                del self._user

                def _cbLogin(parsed):  # noqa: N802
                    self.shell = parsed[1]
                    self.logout = parsed[2]
                    self.workingDirectory = []
                    self.state = self.AUTHED
                    return reply

                def _ebLogin(failure):  # noqa: N802
                    failure.trap(UnauthorizedLogin, UnhandledCredentials)
                    self.state = self.UNAUTH
                    raise AuthorizationError

                d = self.portal.login(creds, None, IFTPShell)
                d.addCallbacks(_cbLogin, _ebLogin)
                return d

        p = Portal(CustomFTPRealm("data"), [CustomAccess()])
        factory = FTPFactory(p)
        factory.protocol = CustomFTPProtocol
        factory.welcomeMessage = "ProFTPD 1.2.10"
        reactor.listenTCP(port=self.port, factory=factory)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from ftplib import FTP as FFTP

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            f = FFTP()
            f.connect(_ip, _port)
            f.login(_username, _password)
            f.pwd()
            f.quit()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        ftpserver = QFTPServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        ftpserver.run_server()
