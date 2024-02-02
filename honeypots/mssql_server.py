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

from binascii import hexlify, unhexlify
from contextlib import suppress
from struct import pack, unpack

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QMSSQLServer(BaseServer):
    NAME = "mssql_server"
    DEFAULT_PORT = 1433

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.file_name = None

    def server_main(self):
        _q_s = self

        class CustomMSSQLProtocol(Protocol):
            _state = None

            def create_payload(self, server_name=b"", token_error_msg=b"", error_code=2):
                with suppress(Exception):
                    if server_name == b"":
                        server_name = b"R&Dbackup"
                    if token_error_msg == b"":
                        token_error_msg = (
                            b"An error has occurred while establishing a connection to the server."
                        )
                    server_name_hex = ("00".join(hex(c)[2:] for c in server_name)).encode(
                        "utf-8"
                    ) + b"00"
                    server_name_hex_len = hexlify(pack("b", len(server_name)))
                    token_error_msg_hex = ("00".join(hex(c)[2:] for c in token_error_msg)).encode(
                        "utf-8"
                    ) + b"00"
                    token_error_msg_hex_len = hexlify(pack("<H", len(token_error_msg)))
                    error_code_hex = hexlify(pack("<I", error_code))
                    token_error_hex = (
                        error_code_hex
                        + b"010e"
                        + token_error_msg_hex_len
                        + token_error_msg_hex
                        + server_name_hex_len
                        + server_name_hex
                        + b"0001000000"
                    )
                    token_done_hex = b"fd020000000000000000000000"
                    token_error_len = hexlify(pack("<H", len(unhexlify(token_error_hex))))
                    data_stream = (
                        b"0401007600350100aa" + token_error_len + token_error_hex + token_done_hex
                    )
                    return (
                        data_stream[0:4]
                        + hexlify(pack(">H", len(unhexlify(data_stream))))
                        + data_stream[8:]
                    )

            def connectionMade(self):
                self._state = 1
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):
                if self._state == 1:
                    version = b"11000000"
                    if data[0] == 0x12:
                        self.transport.write(
                            unhexlify(
                                b"0401002500000100000015000601001b000102001c000103001d0000ff"
                                + version
                                + b"00000200"
                            )
                        )
                    elif data[0] == 0x10:
                        value_start, value_length = unpack("=HH", data[48:52])
                        username = (
                            data[8 + value_start : 8 + value_start + (value_length * 2)]
                            .replace(b"\x00", b"")
                            .decode("utf-8")
                        )
                        value_start, value_length = unpack("=HH", data[52:56])
                        password = data[8 + value_start : 8 + value_start + (value_length * 2)]
                        password = password.replace(b"\x00", b"").replace(b"\xa5", b"")
                        password_decrypted = ""
                        for x in password:
                            password_decrypted += chr(
                                ((x ^ 0xA5) & 0x0F) << 4 | ((x ^ 0xA5) & 0xF0) >> 4
                            )
                        username = check_bytes(username)
                        password = check_bytes(password_decrypted)
                        peer = self.transport.getPeer()
                        _q_s.check_login(username, password, ip=peer.host, port=peer.port)

                        self.transport.write(
                            unhexlify(
                                self.create_payload(
                                    token_error_msg=b"Login Failed", error_code=18456
                                )
                            )
                        )
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = CustomMSSQLProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from pymssql import connect as pconnect

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            conn = pconnect(
                host=_ip, port=str(_port), user=_username, password=_password, database="dbname"
            )
            cursor = conn.cursor()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QMSSQLServer = QMSSQLServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        QMSSQLServer.run_server()
