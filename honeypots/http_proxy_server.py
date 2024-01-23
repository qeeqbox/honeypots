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

from pathlib import Path
from shlex import split

from dns.resolver import resolve as dsnquery
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory
from subprocess import Popen
from email.parser import BytesParser
from os import getenv
from honeypots.helper import (
    close_port_wrapper,
    get_free_port,
    kill_server_wrapper,
    server_arguments,
    set_up_error_logging,
    setup_logger,
    set_local_vars,
    check_if_server_is_running,
)
from uuid import uuid4
from contextlib import suppress


DUMMY_TEMPLATE = (Path(__file__).parent / "data" / "dummy_page.html").read_text()


class QHTTPProxyServer:
    NAME = "http_proxy_server"

    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.uuid = "honeypotslogger" + "_" + __class__.__name__ + "_" + str(uuid4())[:8]
        self.config = kwargs.get("config", "")
        self.template: str | None = None
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get("ip", None) or (hasattr(self, "ip") and self.ip) or "0.0.0.0"
        self.port = (
            (kwargs.get("port", None) and int(kwargs.get("port", None)))
            or (hasattr(self, "port") and self.port)
            or 8080
        )
        self.options = (
            kwargs.get("options", "")
            or (hasattr(self, "options") and self.options)
            or getenv("HONEYPOTS_OPTIONS", "")
            or ""
        )
        self.logger = set_up_error_logging()
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

    def http_proxy_server_main(self):
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
                    _q_s.logs.info(
                        {
                            "server": _q_s.NAME,
                            "action": "query",
                            "src_ip": self.transport.getPeer().host,
                            "src_port": self.transport.getPeer().port,
                            "dest_ip": _q_s.ip,
                            "dest_port": _q_s.port,
                            "data": host[0],
                        }
                    )
                    return dsnquery(host[0], "A")[0].address
                return None

            def dataReceived(self, data):  # noqa: N802
                _q_s.logs.info(
                    {
                        "server": _q_s.NAME,
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                        "dest_ip": _q_s.ip,
                        "dest_port": _q_s.port,
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

    def run_server(self, process=False, auto=False) -> bool | None:
        status = "error"
        run = False
        if not process:
            self.http_proxy_server_main()
            return None

        if auto and not self.auto_disabled:
            port = get_free_port()
            if port > 0:
                self.port = port
                run = True
        elif self.close_port() and self.kill_server():
            run = True

        if run:
            self.process = Popen(
                split(
                    f"python3 {Path(__file__)} --custom --ip {self.ip} --port {self.port} "
                    f"--options '{self.options}' --config '{self.config}' --uuid {self.uuid}"
                )
            )
            if self.process.poll() is None and check_if_server_is_running(self.uuid):
                status = "success"

        self.logs.info(
            {
                "server": self.NAME,
                "action": "process",
                "status": status,
                "src_ip": self.ip,
                "src_port": self.port,
                "dest_ip": self.ip,
                "dest_port": self.port,
            }
        )

        if status == "success":
            return True
        self.kill_server()
        return False

    def close_port(self):
        return close_port_wrapper(self.NAME, self.ip, self.port, self.logs)

    def kill_server(self):
        return kill_server_wrapper(self.NAME, self.uuid, self.process)

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
