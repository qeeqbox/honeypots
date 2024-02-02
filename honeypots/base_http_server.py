from __future__ import annotations

from abc import ABC
from cgi import FieldStorage
from contextlib import suppress
from random import choice

from twisted.web.resource import Resource

from honeypots.base_server import BaseServer
from honeypots.helper import load_template, get_headers_and_ip_from_request, check_bytes


class BaseHttpServer(BaseServer, ABC):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mocking_server = choice(
            [
                "Apache",
                "nginx",
                "Microsoft-IIS/7.5",
                "Microsoft-HTTPAPI/2.0",
                "Apache/2.2.15",
                "SmartXFilter",
                "Microsoft-IIS/8.5",
                "Apache/2.4.6",
                "Apache-Coyote/1.1",
                "Microsoft-IIS/7.0",
                "Apache/2.4.18",
                "AkamaiGHost",
                "Apache/2.2.25",
                "Microsoft-IIS/10.0",
                "Apache/2.2.3",
                "nginx/1.12.1",
                "Apache/2.4.29",
                "cloudflare",
                "Apache/2.2.22",
            ]
        )

    class MainResource(Resource):
        isLeaf = True  # noqa: N815
        home_file = load_template("home.html")
        login_file = load_template("login.html")

        def __init__(self, *args, hp_server: BaseHttpServer = None, **kwargs):
            super().__init__(*args, **kwargs)
            self.hp_server = hp_server
            self.headers = {}

        def render(self, request):
            client_ip, headers = get_headers_and_ip_from_request(request, self.hp_server.options)

            with suppress(Exception):
                log_data = {
                    "action": "connection",
                    "src_ip": client_ip,
                    "src_port": request.getClientAddress().port,
                }
                if "capture_commands" in self.hp_server.options:
                    log_data["data"] = headers
                self.hp_server.log(log_data)

            if self.hp_server.mocking_server != "":
                request.responseHeaders.removeHeader("Server")
                request.responseHeaders.addRawHeader("Server", self.hp_server.mocking_server)

            if request.method in (b"GET", b"POST"):
                self.hp_server.log(
                    {
                        "action": request.method.decode(),
                        "src_ip": client_ip,
                        "src_port": request.getClientAddress().port,
                    }
                )

            if request.method == b"GET":
                if (
                    request.uri == b"/login.html"
                    and self.hp_server.username != ""
                    and self.hp_server.password != ""
                ):
                    request.responseHeaders.addRawHeader(
                        "Content-Type", "text/html; charset=utf-8"
                    )
                    return self.login_file

                request.responseHeaders.addRawHeader("Content-Type", "text/html; charset=utf-8")
                return self.login_file

            if request.method == b"POST":
                self.headers = request.getAllHeaders()
                if (
                    request.uri in (b"/login.html", b"/")
                    and self.hp_server.username != ""
                    and self.hp_server.password != ""
                ):
                    form = FieldStorage(
                        fp=request.content,
                        headers=self.headers,
                        environ={
                            "REQUEST_METHOD": "POST",
                            "CONTENT_TYPE": self.headers.get(
                                b"content-type",
                                b"application/x-www-form-urlencoded",
                            ),
                        },
                    )
                    if "username" in form and "password" in form:
                        username = check_bytes(form["username"].value)
                        password = check_bytes(form["password"].value)
                        self.hp_server.check_login(
                            username, password, client_ip, request.getClientAddress().port
                        )

            request.responseHeaders.addRawHeader("Content-Type", "text/html; charset=utf-8")
            return self.home_file
