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

from twisted.protocols.sip import Base
from twisted.internet import reactor
from time import time
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QSIPServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 5060
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def sip_server_main(self):
        _q_s = self

        class CustomSIPServer(Base):
            def handle_request(self, message, addr):
                headers = {}

                _q_s.logs.info({'server': 'sip_server', 'action': 'connection', 'src_ip': addr[0], 'src_port': addr[1]})

                def check_bytes(string):
                    if isinstance(string, bytes):
                        return string.decode()
                    else:
                        return str(string)
                for item, value in message.headers.items():
                    headers.update({check_bytes(item): ','.join(map(check_bytes, value))})

                _q_s.logs.info({'server': 'sip_server', 'action': 'request', 'src_ip': addr[0], 'src_port': addr[1], 'data': headers})
                response = self.responseFromRequest(200, message)
                response.creationFinished()
                self.deliverResponse(response)

        reactor.listenUDP(port=self.port, protocol=CustomSIPServer(), interface=self.ip)
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

            self.logs.info({'server': 'sip_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.sip_server_main()

    def close_port(self):
        ret = close_port_wrapper('sip_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('sip_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from socket import socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            sock.sendto(b'INVITE sip:user_1@test.test SIP/2.0\r\nTo: <sip:user_2@test.test>\r\nFrom: sip:user_3@test.test.test;tag=none\r\nCall-ID: 1@0.0.0.0\r\nCSeq: 1 INVITE\r\nContact: sip:user_3@test.test.test\r\nVia: SIP/2.0/TCP 0.0.0.0;branch=34uiddhjczqw3mq23\r\nContent-Length: 1\r\n\r\nT', (_ip, _port))
            sock.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSIPServer = QSIPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        QSIPServer.run_server()
