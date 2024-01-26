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

from binascii import unhexlify
from contextlib import suppress

from Crypto.Cipher import DES
from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QVNCServer(BaseServer):
    NAME = "vnc_server"
    DEFAULT_PORT = 5900

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.challenge = unhexlify("00000000901234567890123456789012")
        self.words = ["test"]

    def load_words(
        self,
    ):
        with open(self.file_name) as file:
            self.words = file.read().splitlines()

    def decode(self, c, r):
        with suppress(Exception):
            for word in self.words:
                temp = word
                word = word.strip("\n").ljust(8, "\00")[:8]
                rev_word = []
                for i in range(8):
                    rev_word.append(chr(int(f"{ord(word[i]):08b}"[::-1], 2)))
                output = DES.new("".join(rev_word).encode("utf-8"), DES.MODE_ECB).encrypt(c)
                if output == r:
                    return temp
        return None

    def server_main(self):
        _q_s = self

        class CustomVNCProtocol(Protocol):
            _state = None

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                self.transport.write(b"RFB 003.008\n")
                self._state = 1
                _q_s.logs.info(
                    {
                        "server": "vnc_server",
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
                    }
                )

            def dataReceived(self, data):
                if self._state == 1:
                    if data == b"RFB 003.008\n":
                        self._state = 2
                        self.transport.write(unhexlify("0102"))
                elif self._state == 2:
                    if data == b"\x02":
                        self._state = 3
                        self.transport.write(_q_s.challenge)
                elif self._state == 3:
                    with suppress(Exception):
                        username = self.check_bytes(_q_s.decode(_q_s.challenge, data.hex()))
                        password = self.check_bytes(data)
                        status = "failed"
                        # may need decode
                        if username == _q_s.username and password == _q_s.password:
                            username = _q_s.username
                            password = _q_s.password
                            status = "success"
                        else:
                            password = data.hex()
                        _q_s.logs.info(
                            {
                                "server": "vnc_server",
                                "action": "login",
                                "status": status,
                                "src_ip": self.transport.getPeer().host,
                                "src_port": self.transport.getPeer().port,
                                "dest_ip": _q_s.ip,
                                "dest_port": _q_s.port,
                                "username": username,
                                "password": password,
                            }
                        )
                    self.transport.loseConnection()
                else:
                    self.transport.loseConnection()

            def connectionLost(self, reason):
                self._state = None

        factory = Factory()
        factory.protocol = CustomVNCProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            ip or self.ip
            port or self.port
            username or self.username
            password or self.password
            # client = vncapi.connect('{}::{}'.format(self.ip, self.port), password=password)
            # client.captureScreen('screenshot.png')
            # client.disconnect()


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
