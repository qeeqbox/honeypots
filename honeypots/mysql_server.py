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
from hashlib import sha1
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
        self.words = [self.password.encode()]

    def load_words(
        self,
    ):
        with open(self.file_name, encoding="utf-8") as file:
            self.words = file.read().splitlines()

    def greeting(self):
        base = [
            "\x0a",
            "5.7.00" + "\0",
            "\x36\x00\x00\x00",
            "12345678" + "\0",
            "\xff\xf7",
            "\x21",
            "\x02\x00",
            "\x0f\x81",
            "\x15",
            "\0" * 10,
            "123456789012" + "\0",
            "mysql_native_password" + "\0",
        ]
        payload_len = list(pack("<I", len("".join(base))))
        # payload_len[3] = '\x00'
        string_ = (
            chr(payload_len[0])
            + chr(payload_len[1])
            + chr(payload_len[2])
            + "\x00"
            + "".join(base)
        )
        string_ = bytes([ord(c) for c in string_])
        return string_

    def too_many(self):
        base = ["\xff", "\x10\x04", "#08004", "Too many connections"]
        payload_len = list(pack("<I", len("".join(base))))
        # payload_len[3] = '\x02'
        string_ = (
            chr(payload_len[0])
            + chr(payload_len[1])
            + chr(payload_len[2])
            + "\x02"
            + "".join(base)
        )
        string_ = bytes([ord(c) for c in string_])
        return string_

    def access_denied(self):
        base = ["\xff", "\x15\x04", "#28000", "Access denied.."]
        payload_len = list(pack("<I", len("".join(base))))
        # payload_len[3] = '\x02'
        string_ = (
            chr(payload_len[0])
            + chr(payload_len[1])
            + chr(payload_len[2])
            + "\x02"
            + "".join(base)
        )
        string_ = bytes([ord(c) for c in string_])
        return string_

    def parse_data(self, data):
        with suppress(Exception):
            username_len = data[36:].find(b"\x00")
            username = data[36:].split(b"\x00")[0]
            password_len = data[36 + username_len + 1]
            password = data[36 + username_len + 2 : 36 + username_len + 2 + password_len]
            rest_ = data[36 + username_len + 2 + password_len :]
            if len(password) == 20:
                return username, password, True
        return username, password, False

    def decode(self, hash):
        with suppress(Exception):
            for word in self.words:
                temp = word
                word = word.strip(b"\n")
                hash1 = sha1(word).digest()
                hash2 = sha1(hash1).digest()
                encrypted = [
                    (a ^ b) for a, b in zip(hash1, sha1(b"12345678123456789012" + hash2).digest())
                ]
                if encrypted == list([(i) for i in hash]):
                    return temp
        return None

    def server_main(self):
        _q_s = self

        class CustomMysqlProtocol(Protocol):
            _state = None

            def connectionMade(self):
                self._state = 1
                self.transport.write(_q_s.greeting())
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data):
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

            def connectionLost(self, reason):
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
