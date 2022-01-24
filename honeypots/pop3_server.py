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

from twisted.mail.pop3 import POP3
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from random import choice
from twisted.python import log as tlog
from subprocess import Popen
from os import path
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4


class QPOP3Server():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, config=''):
        self.auto_disabled = None
        self.mocking = mocking or ''
        self.random_servers = ['Microsoft Exchange POP3 service is ready']
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        self.ip = None
        self.port = None
        self.username = None
        self.password = None
        if config:
            self.logs = setup_logger(__class__.__name__, self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = ip or self.ip or '0.0.0.0'
        self.port = port or self.port or 110
        self.username = username or self.username or 'test'
        self.password = password or self.password or 'test'
        disable_logger(1, tlog)

    def pop3_server_main(self):
        _q_s = self

        class CustomPOP3Protocol(POP3):

            self._user = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                _q_s.logs.info({'server': 'pop3_server', 'action': 'connection', 'dest_ip': self.transport.getPeer().host, 'dest_port': self.transport.getPeer().port, 'src_ip': _q_s.ip, 'src_port': _q_s.port})
                self._user = None
                if isinstance(_q_s.mocking, bool):
                    if _q_s.mocking == True:
                        self.successResponse('{}'.format(choice(_q_s.random_servers)))
                elif isinstance(_q_s.mocking, str):
                    self.successResponse('{}'.format(choice(_q_s.random_servers)))
                else:
                    self.successResponse('Connected')

            def do_USER(self, user):
                self._user = user
                self.successResponse('USER Ok')

            def do_PASS(self, password):
                if self._user:
                    username = self.check_bytes(self._user)
                    password = self.check_bytes(password)
                    status = 'failed'
                    if username == _q_s.username and password == _q_s.password:
                        username = _q_s.username
                        password = _q_s.password
                        status = 'success'
                    _q_s.logs.info({'server': 'pop3_server', 'action': 'login', 'status': status, 'dest_ip': self.transport.getPeer().host, 'dest_port': self.transport.getPeer().port, 'src_ip': _q_s.ip, 'src_port': _q_s.port, 'username': username, 'password': password})
                    self.failResponse('Authentication failed')
                else:
                    self.failResponse('USER first, then PASS')

                self._user = None

            def lineReceived(self, line):
                if line.lower().startswith(b'user') or line.lower().startswith(b'pass'):
                    POP3.lineReceived(self, line)
                else:
                    self.failResponse('Authentication failed')

        class CustomPOP3Factory(Factory):
            protocol = CustomPOP3Protocol
            portal = None

            def buildProtocol(self, address):
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        factory = CustomPOP3Factory()
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

            self.logs.info({'server': 'pop3_server', 'action': 'process', 'status': status, 'dest_ip': self.ip, 'dest_port': self.port, 'username': self.username, 'password': self.password})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.pop3_server_main()

    def close_port(self):
        ret = close_port_wrapper('pop3_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('pop3_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            from poplib import POP3 as poplibPOP3
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            pp = poplibPOP3(_ip, _port)
            pp.user(_username)
            pp.pass_(_password)
        except BaseException:
            pass


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qpop3server = QPOP3Server(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        qpop3server.run_server()
