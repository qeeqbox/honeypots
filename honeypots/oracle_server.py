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
from re import findall
from struct import unpack

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QOracleServer(BaseServer):
    NAME = "oracle_server"
    DEFAULT_PORT = 1521

    def server_main(self):
        _q_s = self

        class CustomRedisProtocol(Protocol):
            _state = None

            def wrong_password(self):
                payload = b"\x02B\xc5\xbb\xe7\x7f\x02B\xac\x11\x00\x02\x08\x00E\x00\x01\x02Md@\x00@\x06\x94l\xac\x11\x00\x02\xac\x11\x00\x01\x05\xf1\xa5\xa8\xab\xf5\xff\x94\x98\xdf\xd5\xa1\x80\x18\x01\xf5Y\x1a\x00\x00\x01\x01\x08\nJ\xe7\xf0,\xb2,\xfe\x08\x00\x00\x00\xce\x06\x00\x00\x00\x00\x00\x04\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\xf9\x03\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x006\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x82\x1c\x86u\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf9\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003ORA-01017: invalid username/password; logon denied\n"
                return payload

            def refuse_payload(self):
                payload = b"\x00\x08\x00\x00\x04\x00\x00\x00"
                return payload

            def parse_payload(self, data):
                service_name = None
                program = None
                local_user = None
                with suppress(Exception):
                    (
                        packet_len,
                        packet_checksum,
                        packet_type,
                        packet_reserved_bytes,
                        packet_header_checksum,
                    ) = unpack(">hhbbh", data[0:8])
                    if b"(DESCRIPTION=" in data:
                        connect = data[data.index(b"(DESCRIPTION=") :].split(b"\0")[0]
                        found_temp = findall(rb"[^\(\)]+", connect)
                        if len(found_temp) > 0:
                            found_fixed = [item for item in found_temp if not item.endswith(b"=")]
                            if len(found_fixed) > 0:
                                for item in found_fixed:
                                    name, value = item.split(b"=")
                                    if name.startswith(b"SERVICE_NAME"):
                                        service_name = value.decode()
                                    elif name.startswith(b"PROGRAM"):
                                        program = value.decode()
                                    elif name.startswith(b"USER"):
                                        local_user = value.decode()
                return service_name, program, local_user

            def connectionMade(self):
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):
                service_name, program, local_user = self.parse_payload(data)
                if service_name or program or local_user:
                    _q_s.log(
                        {
                            "action": "login",
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                            "data": {
                                "local_user": local_user,
                                "program": program,
                                "service_name": service_name,
                            },
                        }
                    )
                self.transport.write(self.refuse_payload())
                self.transport.loseConnection()

        factory = Factory()
        factory.protocol = CustomRedisProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings

            filterwarnings(action="ignore", module=".*socket.*")
            from socket import socket, AF_INET, SOCK_STREAM

            payload = b"\x00\x00\x03\x04\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00E\x00\x01F\xb9\xd9@\x00@\x06\x81\xd6\x7f\x00\x00\x01\x7f\x00\x00\x01\xbf\xce\x06\x13\xacW\xde\xc0Z\xb5\x0cI\x80\x18\x02\x00\xff:\x00\x00\x01\x01\x08\n\x1bdZ^\x1bdZ^\x01\x12\x00\x00\x01\x00\x00\x00\x01>\x01,\x0cA \x00\xff\xff\x7f\x08\x00\x00\x01\x00\x00\xc8\x00J\x00\x00\x14\x00AA\xa7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x01(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=xe)(CID=(PROGRAM=linux_1)(HOST=xxxxxxxxxxxxxx)(USER=xxxxxxxxxxxxxx))(CONNECTION_ID=xxxxxxxxxxxxxxxxxxxxxxxx))(ADDRESS=(PROTOCOL=tcp)(HOST=xxxxxxx)(PORT=xxxx)))"
            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.connect((_ip, _port))
            c.send(payload)
            data, address = c.recvfrom(10000)
            c.close()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QOracleServer = QOracleServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QOracleServer.run_server()
