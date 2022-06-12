'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from twisted.protocols.ftp import FTPAnonymousShell, FTPFactory, FTP, AUTH_FAILURE, IFTPShell, GUEST_LOGGED_IN_PROCEED, AuthorizationError, BAD_CMD_SEQ, USR_LOGGED_IN_PROCEED
from twisted.internet import reactor, defer
from twisted.cred.portal import Portal
from twisted.cred import portal, credentials
from twisted.cred.error import UnauthorizedLogin, UnauthorizedLogin, UnhandledCredentials
from twisted.cred.checkers import ICredentialsChecker
from zope.interface import implementer
from twisted.python import filepath
from twisted.python import log as tlog
from random import choice
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress
from tempfile import TemporaryDirectory


class QFTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.mocking_server = choice(['ProFTPD 1.2.10', 'ProFTPD 1.3.4a', 'FileZilla ftp 0.9.43', 'Gene6 ftpd 3.10.0', 'FileZilla ftp 0.9.33', 'ProFTPD 1.2.8'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 21
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.temp_folder = TemporaryDirectory()
        disable_logger(1, tlog)

    def ftp_server_main(self):
        _q_s = self

        @implementer(portal.IRealm)
        class CustomFTPRealm:
            def __init__(self, anonymousRoot):
                self.anonymousRoot = filepath.FilePath(anonymousRoot)

            def requestAvatar(self, avatarId, mind, *interfaces):
                for iface in interfaces:
                    if iface is IFTPShell:
                        avatar = FTPAnonymousShell(self.anonymousRoot)
                        return IFTPShell, avatar, getattr(avatar, 'logout', lambda: None)
                raise NotImplementedError("Only IFTPShell interface is supported by this realm")

        @implementer(ICredentialsChecker)
        class CustomAccess:
            credentialInterfaces = (credentials.IAnonymous, credentials.IUsernamePassword)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def requestAvatarId(self, credentials):
                with suppress(Exception):
                    username = self.check_bytes(credentials.username)
                    password = self.check_bytes(credentials.password)
                    if username == _q_s.username and password == _q_s.password:
                        username = _q_s.username
                        password = _q_s.password
                        return defer.succeed(credentials.username)
                return defer.fail(UnauthorizedLogin())

        class CustomFTPProtocol(FTP):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                _q_s.logs.info({'server': 'ftp_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                self.state = self.UNAUTH
                self.setTimeout(self.timeOut)
                self.reply("220.2", self.factory.welcomeMessage)

            def processCommand(self, cmd, *params):
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'ftp_server', 'action': 'command', 'data': {"cmd": self.check_bytes(cmd.upper()), "args": self.check_bytes(params)}, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                return super().processCommand(cmd, *params)

            def ftp_PASS(self, password):
                username = self.check_bytes(self._user)
                password = self.check_bytes(password)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                _q_s.logs.info({'server': 'ftp_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})

                if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
                    creds = credentials.Anonymous()
                    reply = GUEST_LOGGED_IN_PROCEED
                else:
                    creds = credentials.UsernamePassword(self._user, password)
                    reply = USR_LOGGED_IN_PROCEED

                del self._user

                def _cbLogin(parsed):
                    self.shell = parsed[1]
                    self.logout = parsed[2]
                    self.workingDirectory = []
                    self.state = self.AUTHED
                    return reply

                def _ebLogin(failure):
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

    def run_server(self, process=False, auto=False):
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'ftp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ftp_server_main()
        return None

    def close_port(self):
        ret = close_port_wrapper('ftp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ftp_server', self.uuid, self.process)
        return ret

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


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        ftpserver = QFTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        ftpserver.run_server()
