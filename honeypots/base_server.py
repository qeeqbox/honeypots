from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from os import getenv
from shlex import split
from subprocess import Popen
from typing import Any
from uuid import uuid4

from honeypots.helper import (
    setup_logger,
    set_local_vars,
    set_up_error_logging,
    close_port_wrapper,
    kill_server_wrapper,
    get_free_port,
    check_if_server_is_running,
)


class BaseServer(ABC):
    NAME = "base"
    DEFAULT_PORT = 0
    DEFAULT_USERNAME = "test"
    DEFAULT_PASSWORD = "test"

    def __init__(self, **kwargs):
        self.auto_disabled = None
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

    def close_port(self):
        return close_port_wrapper(self.NAME, self.ip, self.port, self.logs)

    def kill_server(self):
        return kill_server_wrapper(self.NAME, self.uuid, self.process)

    @abstractmethod
    def server_main(self):
        pass

    def run_server(self, process: bool = False, auto: bool = False) -> bool | None:
        status = "error"
        run = False
        if not process:
            self.server_main()
            return None

        if auto and not self.auto_disabled:
            port = get_free_port()
            if port > 0:
                self.port = port
                run = True
        elif self.close_port() and self.kill_server():
            run = True

        if run:
            file = inspect.getfile(self.__class__)
            command = (
                f"python3 {file} --custom --ip {self.ip} " f"--port {self.port} --uuid {self.uuid}"
            )
            if self.options:
                command += f" --options '{self.options}'"
            if self.config:
                command += f" --config '{self.config}'"
            self.process = Popen(split(command))
            if self.process.poll() is None and check_if_server_is_running(self.uuid):
                status = "success"

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
