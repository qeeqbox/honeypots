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

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.python import log as tlog
from struct import pack
from hashlib import sha1
from mysql.connector import connect as mysqlconnect
from subprocess import Popen
from os import path
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars
from uuid import uuid4


class QMysqlServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, dict_=None, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 3306
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.file_name = dict_ or None
        if not dict_:
            self.words = [b"test"]
        else:
            self.load_words()
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)
        disable_logger(1, tlog)

    def load_words(self,):
        with open(self.file_name, 'r', encoding='utf-8') as file:
            self.words = file.read().splitlines()

    def greeting(self):
        base = ['\x0a', '5.7.00' + '\0', '\x36\x00\x00\x00', '12345678' + '\0', '\xff\xf7', '\x21', '\x02\x00', '\x0f\x81', '\x15', '\0' * 10, '123456789012' + '\0', 'mysql_native_password' + '\0']
        payload_len = list(pack('<I', len(''.join(base))))
        #payload_len[3] = '\x00'
        string_ = chr(payload_len[0]) + chr(payload_len[1]) + chr(payload_len[2]) + '\x00' + ''.join(base)
        return string_

    def too_many(self):
        base = ['\xff', '\x10\x04', '#08004', 'Too many connections']
        payload_len = list(pack('<I', len(''.join(base))))
        #payload_len[3] = '\x02'
        string_ = chr(payload_len[0]) + chr(payload_len[1]) + chr(payload_len[2]) + '\x02' + ''.join(base)
        return string_

    def parse_data(self, data):
        username, password = '', ''
        try:
            username_len = data[36:].find(b'\x00')
            username = data[36:].split(b'\x00')[0]
            password_len = data[36 + username_len + 1]
            password = data[36 + username_len + 2:36 + username_len + 2 + password_len]
            rest_ = data[36 + username_len + 2 + password_len:]
            if len(password) == 20:
                #print(":".join("{:02x}".format((c)) for c in password))
                return username, password, True
        except Exception as e:
            pass
        return username, password, False

    def decode(self, hash):
        print(":".join("{:02x}".format((c)) for c in hash))
        try:
            for word in self.words:
                temp = word
                word = word.strip('\n')
                hash1 = sha1(word.encode()).digest()
                hash2 = sha1(hash1).digest()
                encrypted = ''.join(chr((a) ^ (b)) for a, b in zip(hash1, sha1(b'12345678123456789012' + hash2).digest()))
                if encrypted == hash:
                    return temp
        except Exception as e:
            pass

        return None

    def mysql_server_main(self):
        _q_s = self

        class CustomMysqlProtocol(Protocol):

            _state = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                self._state = 1
                self.transport.write(_q_s.greeting().encode())
                _q_s.logs.info(["servers", {'server': 'mysql_server', 'action': 'connection', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port}])

            def dataReceived(self, data):
                if self._state == 1:
                    username, password, good = _q_s.parse_data(data)
                    username = self.check_bytes(username)
                    password = self.check_bytes(password)
                    if good:
                        if password:
                            _x = _q_s.decode(password)
                            if _x == _q_s.password and _x is not None:
                                _q_s.logs.info(["servers", {'server': 'mysql_server', 'action': 'login', 'status': 'success', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port, 'username': _q_s.username, 'password': _q_s.password}])
                            else:
                                _q_s.logs.info(["servers", {'server': 'mysql_server', 'action': 'login', 'status': 'failed', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port, 'username': username, 'password': ':'.join(hex((c))[2:] for c in password)}])
                        else:
                            _q_s.logs.info(["servers", {'server': 'mysql_server', 'action': 'login', 'status': 'failed', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port, 'username': 'UnKnown', 'password': ':'.join(hex((c))[2:] for c in data)}])

                    self.transport.write(_q_s.too_many())
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = CustomMysqlProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def run_server(self, process=False, auto=False):
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'mysql_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'mysql_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'mysql_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'mysql_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'mysql_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.mysql_server_main()

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            cnx = mysqlconnect(user=_username, password=_password, host=_ip, port=_port, database='test', connect_timeout=1000)
            print("31323221s")
        except Exception as e:
            pass

    def close_port(self):
        ret = close_port_wrapper('mysql_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('mysql_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qmysqlserver = QMysqlServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        qmysqlserver.run_server()
