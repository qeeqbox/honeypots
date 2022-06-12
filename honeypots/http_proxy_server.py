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

from dns.resolver import query as dsnquery
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory, Factory
from twisted.python import log as tlog
from subprocess import Popen
from email.parser import BytesParser
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QHTTPProxyServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 8080
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def http_proxy_server_main(self):
        _q_s = self

        class CustomProtocolParent(Protocol):

            def __init__(self):
                self.buffer = None
                self.client = None

            def resolve_domain(self, request_string):
                with suppress(Exception):
                    _, parsed_request = request_string.split(b'\r\n', 1)
                    headers = BytesParser().parsebytes(parsed_request)
                    host = headers['host'].split(':')
                    _q_s.logs.info({'server': 'http_proxy_server', 'action': 'query', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': host[0]})
                    # return '127.0.0.1'
                    return dsnquery(host[0], 'A')[0].address
                return None

            def dataReceived(self, data):
                _q_s.logs.info({'server': 'http_proxy_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                with suppress(Exception):
                    ip = self.resolve_domain(data)
                    if ip:
                        factory = ClientFactory()
                        factory.CustomProtocolParent_ = self
                        factory.protocol = CustomProtocolChild
                        reactor.connectTCP(ip, 80, factory)
                    else:
                        self.transport.loseConnection()

                    if self.client:
                        self.client.write(data)
                    else:
                        self.buffer = data

            def write(self, data):
                self.transport.write(data)

        class CustomProtocolChild(Protocol):
            def connectionMade(self):
                self.write(self.factory.CustomProtocolParent_.buffer)

            def dataReceived(self, data):
                self.factory.CustomProtocolParent_.write(data)

            def write(self, data):
                self.transport.write(data)

        factory = Factory()
        factory.protocol = CustomProtocolParent
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

            self.logs.info({'server': 'http_proxy_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.http_proxy_server_main()

    def close_port(self):
        ret = close_port_wrapper('http_proxy_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('http_proxy_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, domain=None):
        with suppress(Exception):
            from requests import get
            _ip = ip or self.ip
            _port = port or self.port
            _domain = domain or 'http://yahoo.com'
            get(_domain, proxies={'http': 'http://{}:{}'.format(_ip, _port)}).text.encode('ascii', 'ignore')


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qhttpproxyserver = QHTTPProxyServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        qhttpproxyserver.run_server()
