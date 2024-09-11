from contextlib import suppress

from twisted.internet import reactor, ssl
from twisted.web.server import Site

from honeypots.base_http_server import BaseHttpServer
from honeypots.helper import (
    server_arguments,
    create_certificate,
)


class QHTTPSServer(BaseHttpServer):
    NAME = "https_server"
    DEFAULT_PORT = 443

    def server_main(self):
        resource = self.MainResource(hp_server=self)
        with create_certificate() as (cert, key):
            ssl_context = ssl.DefaultOpenSSLContextFactory(key, cert)
            reactor.listenSSL(self.port, Site(resource), ssl_context)
            reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get, post

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get(f"https://{_ip}:{_port}", verify=False)
            post(
                f"https://{_ip}:{_port}",
                data={"username": (None, _username), "password": (None, _password)},
                verify=False,
            )


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qhttpsserver = QHTTPSServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            options=parsed.options,
            config=parsed.config,
        )
        qhttpsserver.run_server()
