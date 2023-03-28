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

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from struct import unpack, calcsize, pack
from time import time
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QNTPServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 123
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def ntp_server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):
            def system_time_to_ntp(self, time_):
                i = (int(time_ + 2208988800.0) << 32)
                f = int(((time_ + 2208988800.0) - int(time_ + 2208988800.0)) * 4294967296)
                return i, f

            def ntp_to_system_time(self, time_):
                i = float(time_ >> 32) - 2208988800.0
                f = float(int(i) & 0xffffffff) / (4294967296)
                return i, f

            def datagramReceived(self, data, addr):
                version = 'UnKnown'
                mode = 'UnKnown'
                success = 'failed'
                unpacked = None
                _q_s.logs.info({'server': 'ntp_server', 'action': 'connection', 'src_ip': addr[0], 'src_port': addr[1]})
                if len(data) == calcsize('!B B B b I I I Q Q Q Q'):
                    version = data[0] >> 3 & 0x7
                    mode = data[0] & 0x7
                    unpacked = unpack('!B B B b I I I Q Q Q Q', data)
                    if unpacked is not None:
                        i, f = self.system_time_to_ntp(time())
                        response = pack('!B B B b I I I Q Q Q Q', 0 << 6 | 3 << 3 | 2, data[1], data[2], data[3], 0, 0, 0, 0, data[10], 0, i + f)
                        self.transport.write(response, addr)
                        success = 'success'

                _q_s.logs.info({'server': 'ntp_server', 'action': 'query', 'status': 'success', 'src_ip': addr[0], 'src_port': addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': {'version': version, 'mode': mode}})
                self.transport.loseConnection()

        reactor.listenUDP(port=self.port, protocol=CustomDatagramProtocolProtocol(), interface=self.ip)
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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'ntp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ntp_server_main()

    def close_port(self):
        ret = close_port_wrapper('ntp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ntp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings
            filterwarnings(action='ignore', module='.*socket.*')
            from socket import socket, AF_INET, SOCK_DGRAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_DGRAM)
            c.sendto(b'\x1b' + 47 * b'\0', (_ip, _port))
            data, address = c.recvfrom(256)
            ret_time = unpack('!12I', data)[10] - 2208988800
            c.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QNTPServer = QNTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        QNTPServer.run_server()
