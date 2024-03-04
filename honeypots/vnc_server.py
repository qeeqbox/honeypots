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
from pathlib import Path

from Crypto.Cipher import DES
from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
)


class QVNCServer(BaseServer):
    NAME = "vnc_server"
    DEFAULT_PORT = 5900

    def __init__(self, **kwargs):
        self.file_name = None
        super().__init__(**kwargs)
        self.challenge = bytes.fromhex("00000000901234567890123456789012")
        self.words = ["test", "admin", "123", "123456"]
        if self.file_name:
            self.load_words()
        self.known_passwords = {self.encode(w): w for w in [*self.words, self.password]}

    def load_words(self):
        path = Path(self.file_name)
        if not path.is_file():
            self.logger.error(f"[{self.NAME}]: Could not load word file: {path}")
            return
        self.words = path.read_text().splitlines()

    def encode(self, word: str) -> bytes:
        temp = word.strip("\n").ljust(8, "\00")[:8]
        rev_word = []
        for i in range(8):
            rev_word.append(int(f"{ord(temp[i]):08b}"[::-1], 2))
        return DES.new(bytes(rev_word), DES.MODE_ECB).encrypt(self.challenge)

    def decode(self, encoded_pw: bytes) -> str | None:
        return self.known_passwords.get(encoded_pw)

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomVNCProtocol(Protocol):
            _state = None

            def connectionMade(self):  # noqa: N802
                self.transport.write(b"RFB 003.008\n")
                self._state = 1
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data: bytes):  # noqa: N802
                if self._state == 1:
                    if data == b"RFB 003.008\n":
                        self._state = 2
                        self.transport.write(bytes.fromhex("0102"))
                elif self._state == 2:  # noqa: PLR2004
                    if data == b"\x02":
                        self._state = 3
                        self.transport.write(_q_s.challenge)
                elif self._state == 3:  # noqa: PLR2004
                    self._handle_login(data)
                    self.transport.loseConnection()
                else:
                    self.transport.loseConnection()

            def _handle_login(self, data: bytes):
                username = ""  # there is no user auth
                password = check_bytes(_q_s.decode(data))
                status = "success" if password == _q_s.password else "failed"
                if password is None:
                    password = f"DES:{data.hex()}"
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

            def connectionLost(self, reason):  # noqa: N802,ARG002
                self._state = None

        factory = Factory()
        factory.protocol = CustomVNCProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        from vncdotool import api

        with suppress(Exception):
            client = api.connect(
                f"{ip or self.ip}::{port or self.port}",
                username=username or self.username,
                password=password or self.password,
            )
            client.captureScreen("screenshot.png")
            client.disconnect()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qvncserver = QVNCServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qvncserver.run_server()
