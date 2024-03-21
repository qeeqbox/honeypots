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
from hashlib import sha1
from pathlib import Path
from struct import pack

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QMysqlServer(BaseServer):
    NAME = "mysql_server"
    DEFAULT_PORT = 3306

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if hasattr(self, "file_name"):
            self.words = Path(self.file_name).read_text("utf-8").splitlines()
        else:
            self.words = [self.password.encode()]

    def greeting(self):
        base = [
            b"\x0a",
            b"5.7.00" + b"\0",
            b"\x36\x00\x00\x00",
            b"12345678" + b"\0",
            b"\xff\xf7",
            b"\x21",
            b"\x02\x00",
            b"\x0f\x81",
            b"\x15",
            b"\0" * 10,
            b"123456789012" + b"\0",
            b"mysql_native_password" + b"\0",
        ]
        return self._create_response(base)

    def too_many(self):
        base = [b"\xff", b"\x10\x04", b"#08004", b"Too many connections"]
        return self._create_response(base, sequence_id=2)

    def access_denied(self):
        base = [b"\xff", b"\x15\x04", b"#28000", b"Access denied.."]
        return self._create_response(base, sequence_id=2)

    @staticmethod
    def _create_response(base: list[bytes], sequence_id: int = 0) -> bytes:
        # MySQL Packets structure: 3 byte payload_len, 1 byte sequence_id, payload
        payload_len = pack("<I", len(b"".join(base)))[:3]
        payload = b"".join(base)
        return payload_len + pack("b", sequence_id) + payload

    @staticmethod
    def parse_data(data: bytes) -> tuple[bytes, bytes, bool]:
        username, password = "", ""
        username_offset = 36
        username_len = data[username_offset:].find(b"\x00")
        if username_len != -1:
            with suppress(IndexError):
                username = data[username_offset : username_offset + username_len]
                password_offset = username_offset + username_len + 2
                password_len = data[password_offset - 1]
                password = data[password_offset : password_offset + password_len]
                if password_len == 20:  # noqa: PLR2004
                    return username, password, True
        return username, password, False

    def decode(self, hash_: bytes):
        with suppress(Exception):
            for word in self.words:
                hash1 = sha1(word.strip(b"\n")).digest()
                hash2 = sha1(hash1).digest()
                encrypted = [
                    (a ^ b) for a, b in zip(hash1, sha1(b"12345678123456789012" + hash2).digest())
                ]
                if encrypted == list(hash_):
                    return word
        return None

    def server_main(self):
        _q_s = self

        class CustomMysqlProtocol(Protocol):
            _state = None

            def connectionMade(self):  # noqa: N802
                self._state = 1
                self.transport.write(_q_s.greeting())
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):  # noqa: N802
                try:
                    if self._state == 1:
                        ret_access_denied = False
                        username, password, good = _q_s.parse_data(data)
                        username = check_bytes(username)
                        status = "failed"
                        if good:
                            if password:
                                password_decoded = _q_s.decode(password)
                                if password_decoded is not None and username == _q_s.username:
                                    password = check_bytes(password_decoded)
                                    status = "success"
                                else:
                                    password = password.hex()
                                    ret_access_denied = True
                            else:
                                ret_access_denied = True
                                password = ":".join(hex(c)[2:] for c in data)
                        _q_s.log(
                            {
                                "action": "login",
                                "status": status,
                                "src_ip": self.transport.getPeer().host,
                                "src_port": self.transport.getPeer().port,
                                "username": username,
                                "password": password,
                            }
                        )

                        if ret_access_denied:
                            self.transport.write(_q_s.access_denied())
                        else:
                            self.transport.write(_q_s.too_many())
                    else:
                        self.transport.loseConnection()
                except BaseException:
                    self.transport.write(_q_s.too_many())
                    self.transport.loseConnection()

            def connectionLost(self, reason):  # noqa: N802,ARG002
                self._state = None

        factory = Factory()
        factory.protocol = CustomMysqlProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from mysql.connector import connect as mysqlconnect

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            mysqlconnect(
                user=_username,
                password=_password,
                host=_ip,
                port=_port,
                database="test",
                connect_timeout=1000,
            )


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qmysqlserver = QMysqlServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qmysqlserver.run_server()
