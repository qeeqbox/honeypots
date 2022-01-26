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

from twisted.mail.imap4 import IMAP4Server
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from random import choice
from twisted import cred
from subprocess import Popen
from os import path
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4


class QIMAPServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, config=''):
        self.auto_disabled = None
        self.mocking = mocking or ''
        self.random_servers = [b'OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.6944.0 DC9 ready']
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.ip = None
        self.port = None
        self.username = None
        self.password = None
        self.config = config
        if config:
            self.logs = setup_logger(__class__.__name__, self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = ip or self.ip or '0.0.0.0'
        self.port = port or self.port or 143
        self.username = username or self.username or 'test'
        self.password = password or self.password or 'test'

    def imap_server_main(self):

        _q_s = self

        class CustomIMAP4Server(IMAP4Server):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                _q_s.logs.info({'server': 'imap_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if isinstance(_q_s.mocking, bool):
                    if _q_s.mocking == True:
                        self.sendPositiveResponse(message=choice(_q_s.random_servers))
                elif isinstance(_q_s.mocking, str):
                    self.sendPositiveResponse(message=choice(_q_s.random_servers))
                else:
                    self.sendPositiveResponse(message=b'Welcome')

            def authenticateLogin(self, user, passwd):
                username = self.check_bytes(user)
                password = self.check_bytes(passwd)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                _q_s.logs.info({'server': 'imap_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})

                raise cred.error.UnauthorizedLogin()

            def lineReceived(self, line):
                try:
                    _line = line.split(b' ')[1]
                    if _line.lower().startswith(b'login') or _line.lower().startswith(b'capability'):
                        IMAP4Server.lineReceived(self, line)
                except BaseException:
                    pass

        class CustomIMAPFactory(Factory):
            protocol = CustomIMAP4Server
            portal = None

            def buildProtocol(self, address):
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        factory = CustomIMAPFactory()
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'imap_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.imap_server_main()

    def close_port(self):
        ret = close_port_wrapper('imap_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('imap_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            from imaplib import IMAP4
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            imap_test = IMAP4(_ip, _port)
            imap_test.login(_username, _password)
        except BaseException:
            pass


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qimapserver = QIMAPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        qimapserver.run_server()
