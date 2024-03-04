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
from email.parser import BytesParser
from pathlib import Path

from dns.resolver import resolve as dsnquery
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    load_template,
)

DUMMY_TEMPLATE = load_template("dummy_page.html")


class QHTTPProxyServer(BaseServer):
    NAME = "http_proxy_server"
    DEFAULT_PORT = 8080

    def __init__(self, **kwargs):
        self.template: str | None = None
        super().__init__(**kwargs)
        self.template_contents: str | None = self._load_template()

    def _load_template(self) -> str | None:
        if self.template:
            try:
                template_contents = Path(self.template).read_text(errors="replace")
                self.logger.debug(
                    f"[{self.NAME}]: Successfully loaded custom template {self.template}"
                )
                return template_contents
            except FileNotFoundError:
                self.logger.error(f"[{self.NAME}]: Template file {self.template} not found")
        return None

    def server_main(self):
        _q_s = self

        class CustomProtocolParent(Protocol):
            def __init__(self):
                self.buffer = None
                self.client = None

            def resolve_domain(self, request_string):
                with suppress(Exception):
                    _, parsed_request = request_string.split(b"\r\n", 1)
                    headers = BytesParser().parsebytes(parsed_request)
                    host = headers["host"].split(":")
                    _q_s.log(
                        {
                            "action": "query",
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                            "data": host[0],
                        }
                    )
                    return dsnquery(host[0], "A")[0].address
                return None

            def dataReceived(self, data):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )
                ip = self.resolve_domain(data)
                if ip:
                    self.write(_create_dummy_response(_q_s.template_contents or DUMMY_TEMPLATE))
                else:
                    self.transport.loseConnection()

                if self.client:
                    self.client.write(data)
                else:
                    self.buffer = data

            def write(self, data):
                self.transport.write(data)

        factory = Factory()
        factory.protocol = CustomProtocolParent
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, domain=None):
        with suppress(Exception):
            from requests import get

            _ip = ip or self.ip
            _port = port or self.port
            _domain = domain or "http://yahoo.com"
            get(_domain, proxies={"http": f"http://{_ip}:{_port}"}).text.encode("ascii", "ignore")


def _create_dummy_response(content: str) -> bytes:
    response = [
        "HTTP/1.1 200 OK",
        f"Content-Length: {len(content)}",
        "",
        f"{content}",
    ]
    return "\r\n".join(response).encode()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qhttpproxyserver = QHTTPProxyServer(
            ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config
        )
        qhttpproxyserver.run_server()
