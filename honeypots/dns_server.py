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

from twisted.names import dns, error, client
from twisted.names.server import DNSServerFactory
from twisted.internet import defer, reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path
from dns.resolver import Resolver
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars
from uuid import uuid4


class QDNSServer():
    def __init__(self, ip=None, port=None, resolver_addresses=None, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 53
        self.resolver_addresses = resolver_addresses or [('8.8.8.8', 53)]
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)
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
                _q_s.logs.info(['servers', {'server': 'dns_server', 'action': 'connection', 'ip': address[0], 'port':address[1]}])
                try:
                    for items in response:
                        for item in items:
                            _q_s.logs.info(['servers', {'server': 'dns_server', 'action': 'query', 'ip': address[0], 'port':address[1], 'payload':item.payload}])
                except Exception as e:
                    _q_s.logs.error(['errors', {'server': 'dns_server', 'error': 'gotResolverResponse', 'type': 'error -> ' + repr(e)}])
                return DNSServerFactory.gotResolverResponse(*args)

        self.resolver = CustomCilentResolver(servers=self.resolver_addresses)
        self.factory = CustomDNSServerFactory(clients=[self.resolver])
        self.protocol = dns.DNSDatagramProtocol(controller=self.factory)
        reactor.listenUDP(self.port, self.protocol, interface=self.ip)
        reactor.listenTCP(self.port, self.factory, interface=self.ip)
        reactor.run()

    def run_server(self, process=False, auto=False):
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--config', str(self.config), '--uuid', str(self.uuid)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'dns_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port}])
                    else:
                        self.logs.info(["servers", {'server': 'dns_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port}])
                else:
                    self.logs.info(["servers", {'server': 'dns_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'dns_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port}])
                else:
                    self.logs.info(["servers", {'server': 'dns_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port}])
        else:
            self.dns_server_main()

    def test_server(self, ip=None, port=None, domain=None):
        try:
            res = Resolver(configure=False)
            res.nameservers = [self.ip]
            res.port = self.port
            temp_domain = domain or "example.org"
            r = res.query(temp_domain, 'a')
        except BaseException:
            pass

    def close_port(self):
        ret = close_port_wrapper('dns_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('dns_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qdnsserver = QDNSServer(ip=parsed.ip, port=parsed.port, resolver_addresses=parsed.resolver_addresses, config=parsed.config)
        qdnsserver.run_server()
