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

from time import sleep
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from struct import unpack
from requests import get
from os import path
from subprocess import Popen
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, set_local_vars
from uuid import uuid4


class QSOCKS5Server():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 1080
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)

    def socks5_server_main(self):
        _q_s = self

        class CustomStreamRequestHandler(StreamRequestHandler):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def handle(self):
                _q_s.logs.info(["servers", {'server': 'socks5_server', 'action': 'connection', 'ip': self.client_address[0], 'port':self.client_address[1]}])
                v, m = unpack("!BB", self.connection.recv(2))
                if v == 5:
                    if 2 in unpack("!" + "B" * m, self.connection.recv(m)):
                        self.connection.sendall(b'\x05\x02')
                        if 1 in unpack("B", self.connection.recv(1)):
                            _len = ord(self.connection.recv(1))
                            username = self.connection.recv(_len)
                            _len = ord(self.connection.recv(1))
                            password = self.connection.recv(_len)
                            username = self.check_bytes(username)
                            password = self.check_bytes(password)
                            if username == _q_s.username and password == _q_s.password:
                                _q_s.logs.info(["servers", {'server': 'socks5_server', 'action': 'login', 'status': 'success', 'ip': self.client_address[0], 'port':self.client_address[1], 'username':_q_s.username, 'password':_q_s.password}])
                            else:
                                _q_s.logs.info(["servers", {'server': 'socks5_server', 'action': 'login', 'status': 'failed', 'ip': self.client_address[0], 'port':self.client_address[1], 'username':username.decode(), 'password':password.decode()}])
                self.server.close_request(self.request)

        class ThreadingTCPServer(ThreadingMixIn, TCPServer):
            pass

        TCPServer.allow_reuse_address = True
        server = ThreadingTCPServer((self.ip, self.port), CustomStreamRequestHandler)
        server.serve_forever()

    def run_server(self, process=False, auto=False):
        if process:
            if self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
        else:
            self.socks5_server_main()

    def run_server(self, process=False, auto=False):
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'socks5_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'socks5_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'socks5_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'socks5_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'socks5_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.socks5_server_main()

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            sleep(2)
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get('https://yahoo.com', proxies=dict(http='socks5://{}:{}@{}:{}'.format(_username, _password, _ip, _port), https='socks5://{}:{}@{}:{}'.format(_username, _password, _ip, _port)))
        except BaseException:
            pass

    def close_port(self):
        ret = close_port_wrapper('socks5_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('socks5_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSOCKS5Server = QSOCKS5Server(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        QSOCKS5Server.run_server()
