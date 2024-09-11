from contextlib import suppress

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import check_bytes, run_single_server

GSSResponse = 112  # password response message


class QPostgresServer(BaseServer):
    NAME = "postgres_server"
    DEFAULT_PORT = 5432

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomPostgresProtocol(Protocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._variables = {}
                self._state = None

            def read_data_custom(self, data: bytes):
                _data = data.decode("utf-8")
                encoded_list = _data[8:-1].split("\x00")
                self._variables = dict(zip(*([iter(encoded_list)] * 2)))

            def read_password_custom(self, data: bytes):
                data = data.decode("utf-8")
                self._variables["password"] = data[5:].split("\x00")[0]

            def connectionMade(self):  # noqa: N802
                self._state = 1
                self._variables = {}
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data: bytes):  # noqa: N802
                print(data.hex())
                if self._state == 1:
                    self._state = 2
                    self.transport.write(b"N")
                elif self._state == 2:  # noqa: PLR2004
                    self.read_data_custom(data)
                    self._state = 3
                    self.transport.write(b"R\x00\x00\x00\x08\x00\x00\x00\x03")
                elif self._state == 3:  # noqa: PLR2004
                    message_type = data[0]
                    print(data.hex())
                    if message_type == GSSResponse and "user" in self._variables:
                        self.read_password_custom(data)
                        username = check_bytes(self._variables["user"])
                        password = check_bytes(self._variables["password"])
                        peer = self.transport.getPeer()
                        _q_s.check_login(username, password, ip=peer.host, port=peer.port)
                    self.transport.loseConnection()
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):  # noqa: N802,ARG002
                self._state = 1
                self._variables = {}

        factory = Factory()
        factory.protocol = CustomPostgresProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from socket import socket

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password

            s = socket()
            s.connect((_ip,_port))
            s.send(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
            s.recv(1024)
            s.send(b'\x00\x00\x00\x21\x00\x03\x00\x00\x75\x73\x65\x72\x00' + _username + b'\x00\x64\x61\x74\x61\x62\x61\x73\x65\x00' + _username + b'\x00\x00')
            s.recv(1024)
            s.send(b'\x70\x00\x00\x00\x09' + _password + b'\x00')
            s.close()


if __name__ == "__main__":
    run_single_server(QPostgresServer)
