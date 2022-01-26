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

from twisted.protocols.ftp import FTPFactory, FTP, AUTH_FAILURE
from twisted.internet import reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4


class QFTPServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking='', config=''):
        self.auto_disabled = None
        self.mocking = mocking or ''
        self.random_servers = ['ProFTPD 1.2.10', 'ProFTPD 1.3.4a', 'FileZilla ftp 0.9.43', 'Gene6 ftpd 3.10.0', 'FileZilla ftp 0.9.33', 'ProFTPD 1.2.8']
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
        self.port = port or self.port or 21
        self.username = username or self.username or 'test'
        self.password = password or self.password or 'test'
        disable_logger(1, tlog)

    def ftp_server_main(self):
        _q_s = self

        class CustomFTPProtocol(FTP):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def ftp_PASS(self, password):
                username = self.check_bytes(self._user)
                password = self.check_bytes(password)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                _q_s.logs.info({'server': 'ftp_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                return AUTH_FAILURE

        class CustomFTPFactory(FTPFactory):
            protocol = CustomFTPProtocol
            portal = None

            def buildProtocol(self, address):
                p = self.protocol()
                p.portal = self.portal
                p.factory = self
                return p

        factory = CustomFTPFactory()
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
        try:
            from ftplib import FTP as FFTP
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            f = FFTP()
            f.connect(_ip, _port)
            f.login(_username, _password)
        except BaseException:
            pass


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        ftpserver = QFTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        ftpserver.run_server()
