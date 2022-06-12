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

from twisted.names import dns, error, client
from twisted.names.server import DNSServerFactory
from twisted.internet import defer, reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QDNSServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.resolver_addresses = [('8.8.8.8', 53)]
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 53
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def dns_server_main(self):
        _q_s = self

        class CustomCilentResolver(client.Resolver):
            def queryUDP(self, queries, timeout=2):
                res = client.Resolver.queryUDP(self, queries, timeout)

                def queryFailed(reason):
                    return defer.fail(error.DomainError())
                res.addErrback(queryFailed)
                return res

        class CustomDNSServerFactory(DNSServerFactory):
            def gotResolverResponse(self, response, protocol, message, address):
                args = (self, response, protocol, message, address)
                _q_s.logs.info({'server': 'dns_server', 'action': 'connection', 'src_ip': address[0], 'src_port': address[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                with suppress(Exception):
                    for items in response:
                        for item in items:
                            _q_s.logs.info({'server': 'dns_server', 'action': 'query', 'src_ip': address[0], 'src_port': address[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': item.payload})
                return DNSServerFactory.gotResolverResponse(*args)

        self.resolver = CustomCilentResolver(servers=self.resolver_addresses)
        self.factory = CustomDNSServerFactory(clients=[self.resolver])
        self.protocol = dns.DNSDatagramProtocol(controller=self.factory)
        reactor.listenUDP(self.port, self.protocol, interface=self.ip)
        reactor.listenTCP(self.port, self.factory, interface=self.ip)
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

            self.logs.info({'server': 'dns_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.dns_server_main()
        return None

    def close_port(self):
        ret = close_port_wrapper('dns_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('dns_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, domain=None):
        with suppress(Exception):
            from dns.resolver import Resolver
            res = Resolver(configure=False)
            res.nameservers = [self.ip]
            res.port = self.port
            temp_domain = domain or 'example.org'
            r = res.query(temp_domain, 'a')


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qdnsserver = QDNSServer(ip=parsed.ip, port=parsed.port, config=parsed.config)
        qdnsserver.run_server()
