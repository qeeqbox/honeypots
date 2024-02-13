from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import suppress
from multiprocessing import Process
from os import getenv
from socket import AF_INET, SOCK_STREAM, socket
from typing import Any
from uuid import uuid4

from psutil import process_iter, TimeoutExpired

from honeypots.helper import (
    get_free_port,
    service_has_started,
    set_local_vars,
    set_up_error_logging,
    setup_logger,
)


class BaseServer(ABC):
    NAME = "base"
    DEFAULT_PORT = 0
    DEFAULT_USERNAME = "test"
    DEFAULT_PASSWORD = "test"

    def __init__(self, **kwargs):
        self.auto_disabled = False
        self.process = None
        self.uuid = f"honeypotslogger_{__class__.__name__}_{str(uuid4())[:8]}"
        self.config = kwargs.get("config", "")
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get("ip", None) or (hasattr(self, "ip") and self.ip) or "0.0.0.0"
        self.port = (
            (kwargs.get("port", None) and int(kwargs.get("port", None)))
            or (hasattr(self, "port") and self.port)
            or self.DEFAULT_PORT
        )
        self.username = (
            kwargs.get("username")
            or (hasattr(self, "username") and self.username)
            or self.DEFAULT_USERNAME
        )
        self.password = (
            kwargs.get("password")
            or (hasattr(self, "password") and self.password)
            or self.DEFAULT_PASSWORD
        )
        self.options = (
            kwargs.get("options", "")
            or (hasattr(self, "options") and self.options)
            or getenv("HONEYPOTS_OPTIONS", "")
            or ""
        )
        self.logger = set_up_error_logging()
        self._server_process: Process | None = None

    def close_port(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((self.ip, self.port)) == 0:
            for process in process_iter():
                with suppress(Exception):
                    for conn in process.connections(kind="inet"):
                        if self.port == conn.laddr.port:
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except TimeoutExpired:
                                process.kill()
        with suppress(OSError):
            sock.bind((self.ip, self.port))
            if sock.connect_ex((self.ip, self.port)) != 0:
                return True
        self.logger.error(f"[{self.NAME}]: Could not close port {self.port}")
        return False

    def kill_server(self):
        if self._server_process:
            try:
                self._server_process.terminate()
                self._server_process.join(timeout=5)
            except TimeoutError:
                self._server_process.kill()

    @abstractmethod
    def server_main(self):
        pass

    def run_server(self, process: bool = False, auto: bool = False) -> bool | None:
        run = False
        if not process:
            self.server_main()
            return None

        if auto and not self.auto_disabled:
            port = get_free_port()
            if port > 0:
                self.port = port
                run = True
        elif self.close_port():
            run = True

        status = self._start_server() if run else "error"

        self.log(
            {
                "action": "process",
                "status": status,
                "src_ip": self.ip,
                "src_port": self.port,
            }
        )

        if status == "success":
            return True
        self.kill_server()
        return False

    def _start_server(self) -> str:
        self._server_process = Process(target=self.server_main)
        self._server_process.start()
        if service_has_started(int(self.port)):
            return "success"
        self.logger.error(f"Server {self.NAME} did not start")
        return "error"

    def check_login(self, username: str, password: str, ip: str, port: int) -> bool:
        status = "success" if self._login_is_correct(username, password) else "failed"
        self.log(
            {
                "action": "login",
                "status": status,
                "src_ip": ip,
                "src_port": port,
                "username": username,
                "password": password,
            }
        )
        return status == "success"

    def _login_is_correct(self, username: str, password: str) -> bool:
        return username == self.username and password == self.password

    def log(self, log_data: dict[str, Any]):
        log_data.update(
            {
                "server": self.NAME,
                "dest_ip": self.ip,
                "dest_port": self.port,
            }
        )
        self.logs.info(log_data)
