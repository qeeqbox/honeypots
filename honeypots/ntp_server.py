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
from contextlib import suppress
from struct import pack, unpack
from time import time

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QNTPServer(BaseServer):
    NAME = "ntp_server"
    DEFAULT_PORT = 123

    def server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):
            def system_time_to_ntp(self, time_):
                i = int(time_ + 2208988800.0) << 32
                f = int(((time_ + 2208988800.0) - int(time_ + 2208988800.0)) * 4294967296)
                return i, f

            def ntp_to_system_time(self, time_):
                i = float(time_ >> 32) - 2208988800.0
                f = float(int(i) & 0xFFFFFFFF) / 4294967296
                return i, f

            def datagramReceived(self, data, addr):
                version = "UnKnown"
                mode = "UnKnown"
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": addr[0],
                        "src_port": addr[1],
                    }
                )
                try:
                    version = data[0] >> 3 & 0x7
                    mode = data[0] & 0x7
                    i, f = self.system_time_to_ntp(time())
                    response = pack(
                        "!B B B b I I I Q Q Q Q",
                        0 << 6 | 3 << 3 | 2,
                        data[1],
                        data[2],
                        data[3],
                        0,
                        0,
                        0,
                        0,
                        data[10],
                        0,
                        i + f,
                    )
                    self.transport.write(response, addr)
                    status = "success"
                except (struct.error, TypeError, IndexError):
                    status = "error"

                _q_s.log(
                    {
                        "action": "query",
                        "status": status,
                        "src_ip": addr[0],
                        "src_port": addr[1],
                        "data": {"version": version, "mode": mode},
                    }
                )

        reactor.listenUDP(
            port=self.port, protocol=CustomDatagramProtocolProtocol(), interface=self.ip
        )
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings

            filterwarnings(action="ignore", module=".*socket.*")
            from socket import socket, AF_INET, SOCK_DGRAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_DGRAM)
            c.sendto(b"\x1b" + 47 * b"\0", (_ip, _port))
            data, address = c.recvfrom(256)
            ret_time = unpack("!12I", data)[10] - 2208988800
            c.close()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QNTPServer = QNTPServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QNTPServer.run_server()
