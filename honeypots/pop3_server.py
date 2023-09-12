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
from typing import Tuple
from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from twisted.mail.pop3 import POP3, POP3Error
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from random import choice
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QPOP3Server():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.mocking_server = choice(['Microsoft Exchange POP3 service is ready'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 110
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
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
                _q_s.logs.info({'server': 'pop3_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                self._user = None
                self.successResponse('{}'.format(_q_s.mocking_server))

            def processCommand(self, command: bytes, *args):

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'pop3_server', 'action': 'command', 'data': {"cmd": self.check_bytes(command), "args": self.check_bytes(b" ".join(args))}, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if not (command.lower().startswith(b'user') or command.lower().startswith(b'pass')):
                    self.failResponse('Authentication failed')
                    return

                if self.blocked is not None:
                    self.blocked.append((command, args))
                    return

                command = command.upper()
                authCmd = command in self.AUTH_CMDS
                if not self.mbox and not authCmd:
                    raise POP3Error(b"not authenticated yet: cannot do " + command)
                f = getattr(self, "do_{}".format(self.check_bytes(command)), None)
                if f:
                    return f(*args)
                raise POP3Error(b"Unknown protocol command: " + command)

            def do_USER(self, user):
                self._user = user
                self.successResponse('USER Ok')

            def do_PASS(self, password: bytes, *words: Tuple[bytes]):
                if self._user:
                    username = self.check_bytes(self._user)
                    password = self.check_bytes(b" ".join((password,) + words))
                    status = 'failed'
                    if username == _q_s.username and password == _q_s.password:
                        username = _q_s.username
                        password = _q_s.password
                        status = 'success'
                    _q_s.logs.info({'server': 'pop3_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                    self.failResponse('Authentication failed')
                else:
                    self.failResponse('USER first, then PASS')

                self._user = None

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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'pop3_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

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
        with suppress(Exception):
            from poplib import POP3 as poplibPOP3
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            pp = poplibPOP3(_ip, _port)
            # pp.getwelcome()
            pp.user(_username)
            pp.pass_(_password)


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qpop3server = QPOP3Server(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qpop3server.run_server()
