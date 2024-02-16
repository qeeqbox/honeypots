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
from pathlib import Path
from random import randint
from tempfile import TemporaryDirectory
from threading import current_thread
from unittest.mock import patch

from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash
from six.moves import socketserver

from honeypots.base_server import BaseServer
from honeypots.helper import (
    hide_stderr,
    run_single_server,
)


class QSMBServer(BaseServer):
    NAME = "smb_server"
    DEFAULT_PORT = 445

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.folders = ""

    def server_main(self):  # noqa: C901
        _q_s = self

        class SMBSERVERHandler(smbserver.SMBSERVERHandler):
            def __init__(self, request, client_address, server, select_poll=False):
                self.__SMB = server
                self.__timeOut = 60 * 10
                self.__request = request
                self.__select_poll = select_poll
                self.__ip, self.__port = client_address[:2]
                self.__connId = f"thread_{self.__ip}_{self.__port}_{randint(1000, 9999)}"
                current_thread().name = self.__connId
                socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

        class SMBServer(smbserver.SMBSERVER):
            def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser=None):
                super().__init__(server_address, handler_class, config_parser)

            def processRequest(self, connId, data):  # noqa: N802,N803
                # hide trace logging from smbserver module
                with hide_stderr():
                    return super().processRequest(connId, data)

            def log(self, msg, level=None):  # noqa: ARG002
                temp = current_thread().name
                if not temp.startswith("thread_") or temp.count("_") < 2:  # noqa: PLR2004
                    return
                _, ip, port, *_ = temp.split("_")
                message = msg.strip()
                if (
                    "Incoming connection" in message
                    or "AUTHENTICATE_MESSAGE" in message
                    or "authenticated successfully" in message
                ):
                    _q_s.log(
                        {
                            "action": "connection",
                            "data": message,
                            "src_ip": ip,
                            "src_port": port,
                        }
                    )
                elif ":aaaaaaaaaaaaaaaa:" in message:
                    with suppress(ValueError):
                        username, _, _, _, nt_res_1, nt_res_2 = message.split(":")
                        _q_s.log(
                            {
                                "action": "login",
                                "username": username,
                                "src_ip": ip,
                                "src_port": port,
                                "data": {"nt_data_1": nt_res_1, "nt_data_2": nt_res_2},
                            }
                        )

        class SimpleSMBServer(smbserver.SimpleSMBServer):
            def __init__(self, listenAddress="0.0.0.0", listenPort=445, configFile=""):  # noqa: N803
                with patch("impacket.smbserver.SMBSERVER", SMBServer):
                    super().__init__(listenAddress, listenPort, configFile)

            def start(self):
                self.__srvsServer.start()
                self.__wkstServer.start()
                self.__server.serve_forever()

        with TemporaryDirectory() as tmpdir:
            server = SimpleSMBServer(listenAddress=self.ip, listenPort=self.port)
            if self.folders == "" or self.folders is None:
                server.addShare("C$", tmpdir, "", readOnly="yes")
            else:
                for folder in self.folders.split(","):
                    name, path = folder.split(":")
                    if Path(path).is_dir() and len(name) > 0:
                        server.addShare(name, path, "", readOnly="yes")

            server.setSMB2Support(True)
            server.addCredential(
                self.username, 0, compute_lmhash(self.password), compute_nthash(self.password)
            )
            server.setSMBChallenge("")
            server.start()

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from impacket.smbconnection import SMBConnection

            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            smb_client = SMBConnection(_ip, _ip, sess_port=_port)
            smb_client.login(_username, _password)


if __name__ == "__main__":
    run_single_server(QSMBServer)
