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
from logging import DEBUG, getLogger, StreamHandler
from os import path
from random import randint
from shutil import rmtree
from tempfile import mkdtemp
from threading import current_thread
from time import sleep

from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash
from six.moves import socketserver

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
)


class QSMBServer(BaseServer):
    NAME = "smb_server"
    DEFAULT_PORT = 445

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.folders = ""

    def server_main(self):
        _q_s = self

        class Logger:
            def write(self, message):
                temp = current_thread().name
                if temp.startswith("thread_"):
                    ip = temp.split("_")[1]
                    port = temp.split("_")[2]
                    if (
                        "Incoming connection" in message.strip()
                        or "AUTHENTICATE_MESSAGE" in message.strip()
                        or "authenticated successfully" in message.strip()
                    ):
                        _q_s.log(
                            {
                                "action": "connection",
                                "data": message.strip(),
                                "src_ip": ip,
                                "src_port": port,
                            }
                        )
                    elif ":aaaaaaaaaaaaaaaa:" in message.strip():
                        parsed = message.strip().split(":")
                        if len(parsed) == 6:
                            username, _, _, _, nt_res_1, nt_res_2 = parsed
                            _q_s.log(
                                {
                                    "action": "login",
                                    "username": username,
                                    "src_ip": ip,
                                    "src_port": port,
                                    "data": {"nt_data_1": nt_res_1, "nt_data_2": nt_res_2},
                                }
                            )

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

        class SMBSERVER(smbserver.SMBSERVER):
            def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser=None):
                super().__init__(server_address, handler_class, config_parser)

            def processRequest(self, connId, data):
                x = super().processRequest(connId, data)
                return x

        class SimpleSMBServer(smbserver.SimpleSMBServer):
            def __init__(self, listenAddress="0.0.0.0", listenPort=445, configFile=""):
                super().__init__(listenAddress, listenPort, configFile)
                self.__server.server_close()
                sleep(randint(1, 2))
                self.__server = SMBSERVER(
                    (listenAddress, listenPort), config_parser=self.__smbConfig
                )
                self.__server.processConfigFile()

            def start(self):
                self.__srvsServer.start()
                self.__wkstServer.start()
                self.__server.serve_forever()

        handler = StreamHandler(Logger())
        getLogger("impacket").addHandler(handler)
        getLogger("impacket").setLevel(DEBUG)

        dirpath = mkdtemp()
        server = SimpleSMBServer(listenAddress=self.ip, listenPort=self.port)
        # server.removeShare('IPC$')
        if self.folders == "" or self.folders is None:
            server.addShare("C$", dirpath, "", readOnly="yes")
        else:
            for folder in self.folders.split(","):
                name, d = folder.split(":")
                if path.isdir(d) and len(name) > 0:
                    server.addShare(name, d, "", readOnly="yes")

        server.setSMB2Support(True)
        server.addCredential(
            self.username, 0, compute_lmhash(self.password), compute_nthash(self.password)
        )
        server.setSMBChallenge("")
        server.start()
        rmtree(dirpath)

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
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmbserver = QSMBServer(
            ip=parsed.ip,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            folders=parsed.folders,
            options=parsed.options,
            config=parsed.config,
        )
        qsmbserver.run_server()
