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

import struct
from socket import inet_aton

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol

from honeypots.base_server import BaseServer
from honeypots.helper import check_bytes, server_arguments


class QDHCPServer(BaseServer):
    NAME = "dhcp_server"
    DEFAULT_PORT = 67

    def server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):
            def payload(self, value, message):
                (
                    op,
                    htype,
                    hlen,
                    hops,
                    xid,
                    secs,
                    flags,
                    ciaddr,
                    yiaddr,
                    siaddr,
                    giaddr,
                    chaddr,
                ) = struct.unpack("1s1s1s1s4s2s2s4s4s4s4s16s", message[:44])
                # op, htype, hlen, hops, xid, secs, flags, ciaddr
                response = b"\x02\x01\x06\x00" + xid + b"\x00\x00\x00\x00\x00\x00\x00\x00"
                # yiaddr, siaddr, giaddr, chaddr
                response += (
                    inet_aton(_q_s.dhcp_ip_lease)
                    + inet_aton(_q_s.dhcp_ip)
                    + inet_aton("0.0.0.0")
                    + chaddr
                )
                # sname, file, magic
                response += b"\x00" * 64 + b"\x00" * 128 + b"\x63\x82\x53\x63"
                # options
                response += bytes([53, 1, value])
                response += bytes([54, 4]) + inet_aton(_q_s.dhcp_ip)
                response += bytes([1, 4]) + inet_aton(_q_s.subnet_mask)
                response += bytes([3, 4]) + inet_aton(_q_s.router)
                response += bytes([6, 4]) + inet_aton(_q_s.dns_server)
                response += bytes([51, 4]) + b"\x00\x00\xa8\xc0"  # lease
                response += b"\xff"
                return response

            def parse_options(self, raw):
                options = {}
                tag_name = None
                tag_size = None
                tag = ""
                for b in raw:
                    if tag_name is None:
                        tag_name = b
                    elif tag_name is not None and tag_size is None:
                        tag_size = b
                        tag = ""
                    elif tag_size:
                        tag_size -= 1
                        tag += chr(b)
                        if tag_size == 0:
                            options.update({check_bytes(tag_name): check_bytes(tag)})
                            tag_name = None
                            tag_size = None
                            tag = ""
                return options

            def datagramReceived(self, data, addr):  # noqa: N802
                try:
                    mac_address = struct.unpack("!28x6s", data[:34])[0].hex(":")
                except struct.error:
                    mac_address = "None"
                data = self.parse_options(data[240:])
                data.update({"mac_address": mac_address})
                _q_s.log(
                    {
                        "action": "query",
                        "status": "success",
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "data": data,
                    }
                )

        reactor.listenUDP(
            port=self.port, protocol=CustomDatagramProtocolProtocol(), interface=self.ip
        )
        reactor.run()

    def test_server(self, ip=None, port=None):
        pass


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qdhcpserver = QDHCPServer(
            ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config
        )
        qdhcpserver.run_server()
