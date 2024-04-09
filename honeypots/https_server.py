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

from twisted.internet import reactor, ssl
from twisted.web.server import Site

from honeypots.base_http_server import BaseHttpServer
from honeypots.helper import (
    create_certificate,
    run_single_server,
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
    run_single_server(QHTTPSServer)
