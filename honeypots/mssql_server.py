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
from subprocess import Popen
from os import path
from struct import unpack, pack
from binascii import unhexlify, hexlify
from pymssql import connect as pconnect
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars
from uuid import uuid4


class QMSSQLServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, dict_=None, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 1433
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.file_name = dict_ or None
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)
        disable_logger(1, tlog)

    def mssql_server_main(self):
        _q_s = self

        class CustomMSSQLProtocol(Protocol):

            _state = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def create_payload(self, server_name=b"", token_error_msg=b"", error_code=2):
                ret = "040100c000350100aaa80002000000010e440041006e0020006500720072006f007200200068006100730020006f00630063007500720072006500640020007700680069006c0065002000650073007400610062006c0069007300680069006e00670020006100200063006f006e006e0065006300740069006f006e00200074006f00200074006800650020007300650072007600650072002e00095200260044006200610063006b00750070000001000000fd020000000000000000000000"
                try:
                    if server_name == b"":
                        server_name = b"R&Dbackup"
                    if token_error_msg == b"":
                        token_error_msg = b"An error has occurred while establishing a connection to the server."
                    server_name_hex = ('00'.join(hex(c)[2:] for c in server_name)).encode("utf-8") + b"00"
                    server_name_hex_len = hexlify(pack("b", len(server_name)))
                    token_error_msg_hex = ('00'.join(hex(c)[2:] for c in token_error_msg)).encode("utf-8") + b"00"
                    token_error_msg_hex_len = hexlify(pack("<H", len(token_error_msg)))
                    error_code_hex = hexlify(pack("<I", error_code))
                    token_error_hex = error_code_hex + b"010e" + token_error_msg_hex_len + token_error_msg_hex + server_name_hex_len + server_name_hex + b"0001000000"
                    token_done_hex = b"fd020000000000000000000000"
                    token_error_len = hexlify(pack("<H", len(unhexlify(token_error_hex))))
                    data_stream = b"0401007600350100aa" + token_error_len + token_error_hex + token_done_hex
                    ret = data_stream[0:4] + hexlify(pack(">H", len(unhexlify(data_stream)))) + data_stream[8:]
                except BaseException:
                    pass
                return ret

            def connectionMade(self):
                self._state = 1
                _q_s.logs.info(["servers", {'server': 'mssql_server', 'action': 'connection', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port}])

            def dataReceived(self, data):
                if self._state == 1:
                    version = b"11000000"
                    if(data[0] == 0x12):
                        self.transport.write(unhexlify(b"0401002500000100000015000601001b000102001c000103001d0000ff" + version + b"00000200"))
                    elif(data[0] == 0x10):
                        value_start, value_length = unpack('=HH', data[48:52])
                        username = data[8 + value_start:8 + value_start + (value_length * 2)].replace(b'\x00', b'').decode('utf-8')
                        value_start, value_length = unpack('=HH', data[52:56])
                        password = data[8 + value_start:8 + value_start + (value_length * 2)]
                        password = password.replace(b'\x00', b'').replace(b'\xa5', b'')
                        password_decrypted = ""
                        for x in password:
                            password_decrypted += chr(((x ^ 0xa5) & 0x0F) << 4 | ((x ^ 0xa5) & 0xF0) >> 4)
                        username = self.check_bytes(username)
                        password_decrypted = self.check_bytes(password_decrypted)
                        if username == _q_s.username and password_decrypted == _q_s.password:
                            _q_s.logs.info(["servers", {'server': 'mssql_server', 'action': 'login', 'status': 'success', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port, 'username': _q_s.username, 'password': _q_s.password}])
                        else:
                            _q_s.logs.info(["servers", {'server': 'mssql_server', 'action': 'login', 'status': 'failed', 'ip': self.transport.getPeer().host, 'port': self.transport.getPeer().port, 'username': username, 'password': password_decrypted}])
                        self.transport.write(unhexlify(self.create_payload(token_error_msg=b"Login Failed", error_code=18456)))
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = CustomMSSQLProtocol
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
                        self.logs.info(["servers", {'server': 'mssql_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'mssql_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'mssql_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'mssql_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'mssql_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.mssql_server_main()

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            conn = pconnect(host=_ip, port=str(_port), user=_username, password=_password, database='dbname')
            cursor = conn.cursor()
        except Exception as e:
            pass

    def close_port(self):
        ret = close_port_wrapper('mssql_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('mssql_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QMSSQLServer = QMSSQLServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        QMSSQLServer.run_server()
