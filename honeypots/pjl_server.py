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

from contextlib import suppress

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    check_bytes,
    run_single_server,
)


class QPJLServer(BaseServer):
    NAME = "pjl_server"
    DEFAULT_PORT = 9100

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.printer = b"Brother HL-L2360"
        self.template = {
            "ProductName": "Brother HL-L2360",
            "FormatterNumber": "Q910CHL",
            "PrinterNumber": "L2360",
            "ProductSerialNumber": "VNB1897514",
            "ServiceID": "20157",
            "FirmwareDateCode": "20051103",
            "MaxPrintResolution": "900",
            "ControllerNumber": "Q910CHL",
            "DeviceDescription": "Brother HL-L2360",
            "DeviceLang": "ZJS PJL",
            "TotalMemory": "6890816",
            "AvailableMemory": "3706526",
            "Personality": "0",
            "EngFWVer": "10",
            "IPAddress": "172.17.0.2",
            "HWAddress": "0025B395EA01",
        }

    def server_main(self):
        _q_s = self

        class Custompjlrotocol(Protocol):
            _state = None

            def connectionMade(self):  # noqa: N802
                self._state = 1
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):  # noqa: N802
                # Control to PJL (Removed)
                data = data.replace(b"\x1b%-12345X", b"")
                if data.lower().startswith(b"@pjl echo"):
                    self.transport.write(b"@PJL " + data[10:] + b"\x1b")
                elif data.lower().startswith(b"@pjl info id"):
                    self.transport.write(b"@PJL INFO ID\r\n" + _q_s.printer + b"\r\n\x1b")
                elif data.lower().startswith(b"@pjl prodinfo"):
                    prodinfo = "\r\n".join([k + " = " + v for k, v in _q_s.template.items()])
                    self.transport.write(prodinfo.encode("utf-8") + b"\x1b")
                _q_s.log(
                    {
                        "action": "query",
                        "status": "success",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                        "data": {"command": check_bytes(data)},
                    }
                )
                self.transport.loseConnection()

            def connectionLost(self, reason):  # noqa: N802,ARG002
                self._state = None

        factory = Factory()
        factory.protocol = Custompjlrotocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):  # noqa: ARG002
        with suppress(Exception):
            from warnings import filterwarnings

            filterwarnings(action="ignore", module=".*socket.*")
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.sendto(b"\x1b%-12345X@PJL prodinfo", (_ip, _port))
            c.close()


if __name__ == "__main__":
    run_single_server(QPJLServer)
