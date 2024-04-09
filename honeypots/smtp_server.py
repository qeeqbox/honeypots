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

import socket
from asyncore import loop
from base64 import b64decode
from contextlib import suppress
from smtpd import SMTPChannel, SMTPServer

from honeypots.base_server import BaseServer
from honeypots.helper import (
    run_single_server,
)


class QSMTPServer(BaseServer):
    NAME = "smtp_server"
    DEFAULT_PORT = 25

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomSMTPChannel(SMTPChannel):
            def __init__(self, *args, **kwargs):
                fun = None
                try:
                    # don't leak the *actual* hostname
                    fun = socket.getfqdn
                    socket.getfqdn = lambda: "ip-127-0-0-1.ec2.internal"
                    super().__init__(*args, **kwargs)
                finally:
                    if fun:
                        socket.getfqdn = fun

            def found_terminator(self):
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        line = self._emptystring.join(self.received_lines).decode(errors="ignore")
                        command, *rest = line.split(" ")
                        arg = rest[0] if rest else None
                        data = rest[1] if len(rest) > 1 else None
                        if command.upper() not in {"HELO", "EHLO"}:
                            _q_s.log(
                                {
                                    "action": "connection",
                                    "src_ip": self.addr[0],
                                    "src_port": self.addr[1],
                                    "data": {"command": command, "arg": arg, "data": data},
                                }
                            )
                super().found_terminator()

            def smtp_EHLO(self, arg):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.addr[0],
                        "src_port": self.addr[1],
                    }
                )
                if not arg:
                    self.push("501 Syntax: HELO hostname")
                if self.seen_greeting:
                    self.push("503 Duplicate HELO/EHLO")
                else:
                    self.seen_greeting = arg
                    self.push(f"250-{self.fqdn} Hello {arg}")
                    self.push("250-8BITMIME")
                    self.push("250-AUTH LOGIN PLAIN")
                    self.push("250 STARTTLS")

            def smtp_AUTH(self, arg):  # noqa: N802
                with suppress(Exception):
                    if arg.startswith("PLAIN "):
                        _, username, password = (
                            b64decode(arg.split(" ")[1].strip())
                            .decode("utf-8", errors="replace")
                            .split("\0")
                        )
                        _q_s.check_login(username, password, *self.addr)

                self.push("235 Authentication successful")

            def __getattr__(self, name):
                self.smtp_QUIT(0)

        class CustomSMTPServer(SMTPServer):
            def process_message(self, *_, **__):
                return

            def handle_accept(self):
                conn, addr = self.accept()
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": addr[0],
                        "src_port": addr[1],
                    }
                )
                CustomSMTPChannel(self, conn, addr)

        CustomSMTPServer((self.ip, self.port), None)
        loop(timeout=1.1, use_poll=True)

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from smtplib import SMTP

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            s = SMTP(_ip, _port)
            s.ehlo()
            s.login(_username, _password)
            s.sendmail("fromtest", "totest", "Nothing")
            s.quit()


if __name__ == "__main__":
    run_single_server(QSMTPServer)
