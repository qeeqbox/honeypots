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
from re import split as resplit
from struct import unpack
from binascii import unhexlify
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QPJLServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.printer = b'Brother HL-L2360'
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 9100
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.template = {'ProductName': 'Brother HL-L2360',
                         'FormatterNumber': 'Q910CHL',
                         'PrinterNumber': 'L2360',
                         'ProductSerialNumber': 'VNB1897514',
                         'ServiceID': '20157',
                         'FirmwareDateCode': '20051103',
                         'MaxPrintResolution': '900',
                         'ControllerNumber': 'Q910CHL',
                         'DeviceDescription': 'Brother HL-L2360',
                         'DeviceLang': 'ZJS PJL',
                         'TotalMemory': '6890816',
                         'AvailableMemory': '3706526',
                         'Personality': '0',
                         'EngFWVer': '10',
                         'IPAddress': '172.17.0.2',
                         'HWAddress': '0025B395EA01'}
        disable_logger(1, tlog)

    def pjl_server_main(self):
        _q_s = self

        class Custompjlrotocol(Protocol):

            _state = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                self._state = 1
                _q_s.logs.info({'server': 'pjl_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

            def dataReceived(self, data):
                # Control to PJL (Removed)
                data = data.replace(b'\x1b%-12345X', b'')
                if data.lower().startswith(b'@pjl echo'):
                    self.transport.write(b'@PJL ' + data[10:] + b'\x1b')
                elif data.lower().startswith(b'@pjl info id'):
                    self.transport.write(b'@PJL INFO ID\r\n' + _q_s.printer + b'\r\n\x1b')
                elif data.lower().startswith(b'@pjl prodinfo'):
                    prodinfo = '\r\n'.join([k + " = " + v for k, v in _q_s.template.items()])
                    self.transport.write(prodinfo.encode('utf-8') + b'\x1b')
                _q_s.logs.info({'server': 'ntp_server', 'action': 'query', 'status': 'success', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': {'command': self.check_bytes(data)}})
                self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = Custompjlrotocol
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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'pjl_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.pjl_server_main()

    def close_port(self):
        ret = close_port_wrapper('pjl_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('pjl_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings
            filterwarnings(action='ignore', module='.*socket.*')
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.sendto(b'\x1b%-12345X@PJL prodinfo', (_ip, _port))
            c.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qpjlserver = QPJLServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        qpjlserver.run_server()
