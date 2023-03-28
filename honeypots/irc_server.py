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
filterwarnings(action='ignore', module='.*socket.*')

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.words import service
from time import time
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QIRCServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 6667
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def irc_server_main(self):
        _q_s = self

        class CustomIRCProtocol(service.IRCUser):

            def connectionMade(self):
                _q_s.logs.info({'server': 'irc_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

            def handleCommand(self, command, prefix, params):

                def check_bytes(string):
                    if isinstance(string, bytes):
                        return string.decode()
                    else:
                        return str(string)

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'irc_server', 'action': 'command', 'data': {"command": check_bytes(command), "prefix": check_bytes(prefix), "params": check_bytes(params)}, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                service.IRCUser.handleCommand(self, command, prefix, params)

            def dataReceived(self, data):
                #_q_s.logs.info({'server': 'irc_server', 'action': 'command', 'data': check_bytes(data), 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                service.IRCUser.dataReceived(self, data)

            def irc_unknown(self, prefix, command, params):
                pass

            def irc_NICK(self, prefix, params):

                def check_bytes(string):
                    if isinstance(string, bytes):
                        return string.decode()
                    else:
                        return str(string)

                status = False
                username = check_bytes(''.join(params))
                password = check_bytes(self.password)
                if password == check_bytes(_q_s.password):
                    if username == _q_s.username:
                        status = True
                _q_s.logs.info({'server': 'irc_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

        factory = Factory()
        factory.protocol = CustomIRCProtocol
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

            self.logs.info({'server': 'irc_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.irc_server_main()

    def close_port(self):
        ret = close_port_wrapper('irc_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('irc_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings
            filterwarnings(action='ignore', module='.*socket.*')
            from socket import socket, AF_INET, SOCK_STREAM
            from time import sleep

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            c = socket(AF_INET, SOCK_STREAM)
            c.connect((_ip, _port))
            c.setblocking(False)
            c.send("PASS {}\n".format(_password).encode())
            c.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QIRCServer = QIRCServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        QIRCServer.run_server()
