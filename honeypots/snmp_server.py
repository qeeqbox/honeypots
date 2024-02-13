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

from scapy.error import Scapy_Exception
from scapy.layers.snmp import SNMP
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QSNMPServer(BaseServer):
    NAME = "snmp_server"
    DEFAULT_PORT = 161

    def server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):
            def parse_snmp(self, data):
                try:
                    parsed_snmp = SNMP(data)
                    community = parsed_snmp.community.val
                    version = parsed_snmp.version.val
                    oids = " ".join([item.oid.val for item in parsed_snmp.PDU.varbindlist])
                except Scapy_Exception:
                    version = "UnKnown"
                    community = "UnKnown"
                    oids = "UnKnown"
                return version, community, oids

            def datagramReceived(self, data, addr):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "status": "fail",
                        "src_ip": addr[0],
                        "src_port": addr[1],
                    }
                )
                version, community, oids = self.parse_snmp(data)
                if version or community or oids:
                    _q_s.log(
                        {
                            "action": "query",
                            "status": "success",
                            "src_ip": addr[0],
                            "src_port": addr[1],
                            "data": {"version": version, "community": community, "oids": oids},
                        }
                    )
                    self.transport.write(b"Error", addr)

        reactor.listenUDP(
            port=self.port, protocol=CustomDatagramProtocolProtocol(), interface=self.ip
        )
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):  # noqa: ARG002
        try:
            from pysnmp.hlapi import (
                getCmd,
                SnmpEngine,
                CommunityData,
                UdpTransportTarget,
                ContextData,
                ObjectType,
                ObjectIdentity,
            )

            _ip = ip or self.ip
            _port = port or self.port
            g = getCmd(
                SnmpEngine(),
                CommunityData("public"),
                UdpTransportTarget((_ip, _port)),
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.4.1.9.9.618.1.4.1.0")),
            )
            next(g)
        except Exception as error:
            self.logger.exception(f"Error during test of {self.NAME} server: {error}")


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSNMPServer = QSNMPServer(
            ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config
        )
        QSNMPServer.run_server()
