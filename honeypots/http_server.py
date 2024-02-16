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

from twisted.internet import reactor
from twisted.web.server import Site

from honeypots.base_http_server import BaseHttpServer
from honeypots.helper import (
    run_single_server,
)


class QHTTPServer(BaseHttpServer):
    NAME = "http_server"
    DEFAULT_PORT = 80

    def server_main(self):
        resource = self.MainResource(hp_server=self)
        reactor.listenTCP(self.port, Site(resource))
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get, post

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get(f"http://{_ip}:{_port}", verify=False)
            post(
                f"http://{_ip}:{_port}/login.html",
                data={"username": (None, _username), "password": (None, _password)},
            )


if __name__ == "__main__":
    run_single_server(QHTTPServer)
