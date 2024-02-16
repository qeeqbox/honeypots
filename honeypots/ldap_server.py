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

import struct
from binascii import unhexlify
from contextlib import suppress
from struct import unpack

from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory

from honeypots.base_server import BaseServer
from honeypots.helper import (
    check_bytes,
    run_single_server,
)

# authentication with clear text password
AUTH_SIMPLE_BIND = 0x80


class QLDAPServer(BaseServer):
    NAME = "ldap_server"
    DEFAULT_PORT = 389

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomLDAProtocol(Protocol):
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

            @staticmethod
            def parse_ldap_packet(data: bytes) -> tuple[str, str]:
                #                 V
                # 30[20] 0201[02] 60[1b] 0201[03] 04[0a] 7379736261636b757031
                # [80][0a] 7379736261636b757032

                username = ""
                password = ""
                with suppress(IndexError, struct.error):
                    version_offset = data.find(b"\x02\x01\x03")
                    if version_offset > 0:
                        username_start = version_offset + 5
                        username_len = data[username_start - 1]
                        username_end = username_start + username_len
                        username = check_bytes(data[username_start:username_end])
                        auth_type = data[username_end]
                        if auth_type == AUTH_SIMPLE_BIND:
                            if data[username_end + 1] == 0x82:  # noqa: PLR2004
                                # the length of the password needs more than one byte
                                password_start = username_end + 4
                                password_len = unpack(
                                    ">H", data[password_start - 2 : password_start]
                                )[0]
                            else:
                                password_start = username_end + 2
                                password_len = data[password_start - 1]
                            password_end = password_start + password_len
                            password = check_bytes(data[password_start:password_end])

                return username, password

            def dataReceived(self, data):  # noqa: N802
                if self._state == 1:
                    self._state = 2
                    self._check_login(data)
                    self.transport.write(unhexlify(b"300c02010165070a013204000400"))
                elif self._state == 2:  # noqa: PLR2004
                    self._state = 3
                    self._check_login(data)
                    self.transport.write(unhexlify(b"300c02010265070a013204000400"))
                else:
                    self.transport.loseConnection()

            def _check_login(self, data):
                username, password = self.parse_ldap_packet(data)
                if username != "" or password != "":
                    peer = self.transport.getPeer()
                    _q_s.check_login(username, password, ip=peer.host, port=peer.port)

            def connectionLost(self, reason):  # noqa: N802,ARG002
                self._state = None

        factory = Factory()
        factory.protocol = CustomLDAProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from ldap3 import Server, Connection, ALL

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            c = Connection(
                Server(_ip, port=_port, get_info=ALL),
                authentication="SIMPLE",
                user=_username,
                password=_password,
                check_names=True,
                lazy=False,
                client_strategy="SYNC",
                raise_exceptions=True,
            )
            c.open()
            c.bind()


if __name__ == "__main__":
    run_single_server(QLDAPServer)
