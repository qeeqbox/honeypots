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

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from struct import unpack
from binascii import unhexlify
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QLDAPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 389
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def ldap_server_main(self):
        _q_s = self

        class CustomLDAProtocol(Protocol):

            _state = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                self._state = 1
                _q_s.logs.info({'server': 'ldap_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

            def parse_ldap_packet(self, data):

                #                 V
                # 30[20] 0201[02] 60[1b] 0201[03] 04[0a] 7379736261636b757031 [80][0a] 7379736261636b757032

                username = ''
                password = ''
                username_start = 0
                username_end = 0
                password_start = 0
                password_end = 0
                with suppress(Exception):
                    version = data.find(b'\x02\x01\x03')
                    if version > 0:
                        username_start = version + 5
                        username_end = unpack('b', data[version + 4:username_start])[0] + username_start
                        username = data[username_start:username_end]
                        auth_type = data[username_end]
                        if auth_type == 0x80:
                            if data[username_end + 1] == 0x82:
                                password_start = username_end + 4
                                password_end = unpack('>H', data[username_end + 2:username_end + 4])[0] + username_end + 4
                            else:
                                password_start = username_end + 2
                                password_end = unpack('b', data[username_end + 2:username_end + 3])[0] + username_start + 2
                            password = data[password_start:password_end]

                return username, password

            def dataReceived(self, data):
                if self._state == 1:
                    self._state = 2
                    username, password = self.parse_ldap_packet(data)
                    username = self.check_bytes(username)
                    password = self.check_bytes(password)
                    if username != '' or password != '':
                        if username == _q_s.username and password == _q_s.password:
                            _q_s.logs.info({'server': 'ldap_server', 'action': 'login', 'status': 'success', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': _q_s.username, 'password': _q_s.password})
                        else:
                            _q_s.logs.info({'server': 'ldap_server', 'action': 'login', 'status': 'failed', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                    self.transport.write(unhexlify(b'300c02010165070a013204000400'))
                elif self._state == 2:
                    self._state = 3
                    username, password = self.parse_ldap_packet(data)
                    username = self.check_bytes(username)
                    password = self.check_bytes(password)
                    if username != '' or password != '':
                        if username == _q_s.username and password == _q_s.password:
                            _q_s.logs.info({'server': 'ldap_server', 'action': 'login', 'status': 'success', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': _q_s.username, 'password': _q_s.password})
                        else:
                            _q_s.logs.info({'server': 'ldap_server', 'action': 'login', 'status': 'failed', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                    self.transport.write(unhexlify(b'300c02010265070a013204000400'))
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = CustomLDAProtocol
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

            self.logs.info({'server': 'ldap_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ldap_server_main()

    def close_port(self):
        ret = close_port_wrapper('ldap_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ldap_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from ldap3 import Server, Connection, ALL
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            c = Connection(Server(_ip, port=_port, get_info=ALL), authentication='SIMPLE', user=_username, password=_password, check_names=True, lazy=False, client_strategy='SYNC', raise_exceptions=True)
            c.open()
            c.bind()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QLDAPServer = QLDAPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        QLDAPServer.run_server()
