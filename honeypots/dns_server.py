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

from __future__ import annotations

from contextlib import suppress

from twisted.internet import defer, reactor
from twisted.names import dns, error, client
from twisted.names.server import DNSServerFactory

from honeypots.base_server import BaseServer
from honeypots.helper import run_single_server


class QDNSServer(BaseServer):
    NAME = "dns_server"
    DEFAULT_PORT = 53

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver_addresses = [("8.8.8.8", 53)]

    def server_main(self):
        _q_s = self

        class CustomClientResolver(client.Resolver):
            def queryUDP(self, queries, timeout=2):  # noqa: N802
                res = client.Resolver.queryUDP(self, queries, timeout)

                def queryFailed(reason):  # noqa: N802,ARG001
                    return defer.fail(error.DomainError())

                res.addErrback(queryFailed)
                return res

        class CustomDNSServerFactory(DNSServerFactory):
            def gotResolverResponse(self, response, protocol, message, address):  # noqa: N802
                if address is None:
                    src_ip, src_port = "None", "None"
                else:
                    src_ip, src_port = address
                for items in response:
                    for item in items:
                        _q_s.log(
                            {
                                "action": "query",
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "data": item.payload,
                            }
                        )
                return super().gotResolverResponse(response, protocol, message, address)

        class CustomDnsUdpProtocol(dns.DNSDatagramProtocol):
            def datagramReceived(self, data: bytes, addr: tuple[str, int]):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "data": data.decode(errors="replace"),
                    }
                )
                super().datagramReceived(data, addr)

        self.resolver = CustomClientResolver(servers=self.resolver_addresses)
        self.factory = CustomDNSServerFactory(clients=[self.resolver])
        self.protocol = CustomDnsUdpProtocol(controller=self.factory)
        reactor.listenUDP(self.port, self.protocol, interface=self.ip)
        reactor.listenTCP(self.port, self.factory, interface=self.ip)
        reactor.run()

    def test_server(self, *_, domain=None, **__):
        with suppress(Exception):
            from dns.resolver import Resolver

            res = Resolver(configure=False)
            res.nameservers = [self.ip]
            res.port = self.port
            temp_domain = domain or "example.org"
            res.resolve(temp_domain, "a")


if __name__ == "__main__":
    run_single_server(QDNSServer)
