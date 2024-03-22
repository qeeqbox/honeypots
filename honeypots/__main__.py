#!/usr/bin/env python3

from __future__ import annotations

import logging
import sys
from argparse import ArgumentParser, SUPPRESS, Namespace
from atexit import register
from functools import wraps
from json import JSONDecodeError, loads
from os import geteuid
from pathlib import Path
from signal import alarm, SIGALRM, SIGINT, signal, SIGTERM, SIGTSTP
from subprocess import Popen
from time import sleep
from typing import Any
from uuid import uuid4

from netifaces import ifaddresses, AF_INET, AF_LINK, interfaces
from psutil import net_io_counters, Process

from honeypots import (
    QSniffer,
    QDHCPServer,
    QDNSServer,
    QElasticServer,
    QFTPServer,
    QHTTPProxyServer,
    QHTTPSServer,
    QHTTPServer,
    QIMAPServer,
    QIPPServer,
    QIRCServer,
    QLDAPServer,
    QMSSQLServer,
    QMemcacheServer,
    QMysqlServer,
    QNTPServer,
    QOracleServer,
    QPJLServer,
    QPOP3Server,
    QPostgresServer,
    QRDPServer,
    QRedisServer,
    QSIPServer,
    QSMBServer,
    QSMTPServer,
    QSNMPServer,
    QSOCKS5Server,
    QSSHServer,
    QTelnetServer,
    QVNCServer,
    is_privileged,
    clean_all,
    setup_logger,
    set_up_error_logging,
)

all_servers = {
    "dhcp": QDHCPServer,
    "dns": QDNSServer,
    "elastic": QElasticServer,
    "ftp": QFTPServer,
    "httpproxy": QHTTPProxyServer,
    "https": QHTTPSServer,
    "http": QHTTPServer,
    "imap": QIMAPServer,
    "ipp": QIPPServer,
    "irc": QIRCServer,
    "ldap": QLDAPServer,
    "mssql": QMSSQLServer,
    "memcache": QMemcacheServer,
    "mysql": QMysqlServer,
    "ntp": QNTPServer,
    "oracle": QOracleServer,
    "pjl": QPJLServer,
    "pop3": QPOP3Server,
    "postgres": QPostgresServer,
    "rdp": QRDPServer,
    "redis": QRedisServer,
    "sip": QSIPServer,
    "smb": QSMBServer,
    "smtp": QSMTPServer,
    "snmp": QSNMPServer,
    "socks5": QSOCKS5Server,
    "ssh": QSSHServer,
    "telnet": QTelnetServer,
    "vnc": QVNCServer,
}

logger = set_up_error_logging()


class SignalFence:
    def __init__(self, signals_to_listen_on, interval=1):
        self.fence_up = True
        self.interval = interval

        for signal_to_listen_on in signals_to_listen_on:
            signal(signal_to_listen_on, self.handle_signal)

    def handle_signal(self, signum, frame):  # noqa: ARG002
        self.fence_up = False

    def wait_on_fence(self):
        while self.fence_up:
            sleep(self.interval)


class Termination:
    def __init__(self, strategy):
        self.strategy = strategy

    def await_termination(self):
        if self.strategy == "input":
            input("")
        elif self.strategy == "signal":
            SignalFence([SIGTERM, SIGINT, SIGTSTP]).wait_on_fence()
        else:
            raise Exception(f"Unknown termination strategy: {self.strategy}")


def timeout(seconds=10):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def handle_timeout(signum, frame):  # noqa: ARG001
                raise TimeoutError()

            signal(SIGALRM, handle_timeout)
            alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                alarm(0)
            return result

        return wrapper

    return decorator


@timeout(5)
def server_timeout(obj, name):
    try:
        logger.info(f"Start testing {name}")
        obj.test_server()
    except TimeoutError:
        logging.error(f"Timeout during test {name}")
    logger.info(f"Done testing {name}")


class HoneypotsManager:
    def __init__(self, options: Namespace, server_args: dict[str, str | int]):
        self.options = options
        self.server_args = server_args
        self.config_data = self._load_config() if self.options.config else {}
        self.auto = options.auto if geteuid() != 0 else False
        self.honeypots: list[tuple[Any, str, bool]] = []

    def main(self):
        logger.info("For updates, check https://github.com/qeeqbox/honeypots")
        if not is_privileged():
            logger.warning(
                "Using system or well-known ports requires higher privileges (E.g. sudo -E)"
            )

        if self.options.list:
            for service in all_servers:
                print(service)
        elif self.options.kill:
            clean_all()
        elif self.options.chameleon and self.config_data:
            self._start_chameleon_mode()
        elif self.options.setup:
            if self.options.sniffer:
                self._set_up_sniffer()
            self._set_up_honeypots()

    def _load_config(self):
        config_path = Path(self.options.config)
        if not config_path.is_file():
            logger.error(f'Config file "{config_path}" not found')
            sys.exit(1)
        try:
            config_data = loads(config_path.read_text())
            logger.info(f"Successfully loaded config file {config_path}")
            return config_data
        except FileNotFoundError:
            logger.error(f"Unable to load config file: File {config_path} not found")
            sys.exit(1)
        except JSONDecodeError as error:
            logger.error(f"Unable to parse config file as JSON: {error}")
            sys.exit(1)

    def _set_up_honeypots(self):  # noqa: C901
        register(_exit_handler)
        if self.options.termination_strategy == "input":
            logger.info("Use [Enter] to exit or python3 -m honeypots --kill")
        if self.options.config != "":
            logger.warning("config.json file overrides --ip, --port, --username and --password")
        if self.options.setup == "all":
            self._start_all_servers()
        else:
            self._start_configured_servers()

        running_honeypots = {"good": [], "bad": []}
        if len(self.honeypots) > 0:
            for _, server_name, status in self.honeypots:
                if not status:
                    running_honeypots["bad"].append(server_name)
                else:
                    running_honeypots["good"].append(server_name)

            if len(running_honeypots["good"]) > 0:
                running_servers = ", ".join(running_honeypots["good"])
                logger.info(f"servers {running_servers} running...")

            if len(running_honeypots["bad"]) > 0:
                not_running_servers = ", ".join(running_honeypots["bad"])
                logger.warning(f"servers {not_running_servers} not running...")

            if len(running_honeypots["bad"]) == 0:
                logger.info("Everything looks good!")

            if len(running_honeypots["good"]) > 0 and not self.options.test:
                Termination(self.options.termination_strategy).await_termination()

            self._stop_servers()

    def _start_all_servers(self):
        try:
            for service in all_servers:
                self._start_server(service)
        except Exception as error:
            logger.exception(f"Starting honeypots failed: {error}")

    def _start_configured_servers(self):
        for service in self.options.setup.split(","):
            logger.info("Parsing honeypot [normal]")
            if ":" in service:
                service, port = service.split(":")  # noqa: PLW2901
                auto = False
                self.options.port = int(port)
                self.server_args["port"] = self.options.port
            elif self.options.port:
                auto = False
            elif self.options.test:
                logger.error(
                    f"server {service} was configured with random port, unable to test..."
                )
                continue
            else:
                auto = True
            self._start_server(service, auto)

    def _start_server(self, service: str, auto: bool | None = None):
        if auto is None:
            auto = self.auto
        server_class = all_servers.get(service.lower())
        if not server_class:
            logger.warning(f"Skipping unknown service {service}")
            return
        server = server_class(**self.server_args)
        if not self.options.test:
            status = server.run_server(process=True, auto=auto)
        else:
            server_timeout(server, service)
            server.kill_server()
            status = False
        self.honeypots.append((server, service, status))

    def _stop_servers(self):
        logger.info("[x] Stopping servers...")
        for server, name, _ in self.honeypots:
            try:
                logger.info(f"[x] Killing {server.__class__.__name__} server")
                server.kill_server()
            except Exception as error:
                logger.exception(f"Error when killing server {name}: {error}")
        logger.info("[x] Please wait few seconds")
        sleep(5)

    def _start_chameleon_mode(self):  # noqa: C901,PLR0912
        logger.info("[x] Chameleon mode")
        if "db_sqlite" in self.config_data["logs"] or "db_postgres" in self.config_data["logs"]:
            logs = self._setup_logging()
        else:
            logger.error("logging must be configured with db_sqlite or db_postgres")
            sys.exit(1)

        if self.options.config != "":
            logger.warning(
                "[x] Config.json file overrides --ip, --port, --username and --password"
            )

        if self.options.port:
            self.options.port = int(self.options.port)
        self.server_args["port"] = self.options.port

        honeypots = self.config_data["honeypots"]
        if isinstance(honeypots, dict):
            logger.info("[x] Parsing honeypot [hard]")
            for honeypot in honeypots:
                self._start_server(honeypot)
        elif isinstance(honeypots, str):
            logger.info("[x] Parsing honeypot [easy]")
            if ":" in honeypots:
                logger.error(
                    "[!] You cannot bind ports with [:] in this mode, "
                    "use the honeypots dict instead"
                )
                sys.exit(1)
            for server in honeypots.split(","):
                self._start_server(server)
        else:
            logger.error(f"[!] Unable to parse honeypots from config: {honeypots}")
            sys.exit(1)

        if self.options.sniffer:
            self._set_up_sniffer()

        if not self.options.test:
            logger.info("[x] Everything looks good!")
            self._stats_loop(logs)
        else:
            self._stop_servers()

    def _setup_logging(self) -> logging.Logger:
        uuid = f"honeypotslogger_main_{str(uuid4())[:8]}"
        if "db_options" in self.config_data:
            drop = "drop" in self.config_data["db_options"]
            logger.info(f"[x] Setup Logger {uuid} with a db, drop is {drop}")
        else:
            drop = True
        return setup_logger("main", uuid, self.options.config, drop)

    def _set_up_sniffer(self):
        sniffer_filter = self.config_data.get("sniffer_filter")
        sniffer_interface = self.config_data.get("sniffer_interface")
        if not sniffer_interface:
            logger.error('If sniffer is enabled, "sniffer_interface" must be set in the config')
            sys.exit(1)
        if not self.options.test and self.options.sniffer:
            _check_interfaces(sniffer_interface)
            if self.options.iptables:
                _fix_ip_tables()
                logger.info("[x] Wait for iptables update...")
                sleep(2)
        self._start_sniffer(sniffer_filter, sniffer_interface)

    def _start_sniffer(self, sniffer_filter, sniffer_interface):
        logger.info("[x] Starting sniffer")
        sniffer = QSniffer(
            filter_=sniffer_filter,
            interface=sniffer_interface,
            config=self.options.config,
        )
        sniffer.run_sniffer(process=True)
        sleep(0.1)
        self.honeypots.append((sniffer, "sniffer", sniffer.server_is_alive()))

    def _stats_loop(self, logs):
        while True:
            try:
                network_stats = {
                    "type": "network",
                    "bytes_sent": net_io_counters().bytes_sent,
                    "bytes_recv": net_io_counters().bytes_recv,
                    "packets_sent": net_io_counters().packets_sent,
                    "packets_recv": net_io_counters().packets_recv,
                }
                logs.info(["system", network_stats])
                load_stats = {
                    server.__class__.__name__: {
                        "memory": Process(server.process.pid).memory_percent(),
                        "cpu": Process(server.process.pid).cpu_percent(),
                    }
                    for server, *_ in self.honeypots
                }
                logs.info(["system", load_stats])
            except Exception as error:
                logger.exception(f"An error occurred during stats logging: {error}")
            sleep(20)


def _fix_ip_tables():
    try:
        logger.info("[x] Fixing iptables")
        Popen(
            "iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP",
            shell=True,
        )
    except Exception as error:
        logger.exception(f"Could not fix iptables: {error}")


def _check_interfaces(sniffer_interface):
    current_interfaces = "unknown"
    try:
        current_interfaces = " ".join(interfaces())
        if sniffer_interface not in current_interfaces:
            logger.error(
                f"[!] Sniffer interface {sniffer_interface} not found in current interfaces"
            )
            sys.exit(1)
        ip_address = ifaddresses(sniffer_interface)[AF_INET][0]["addr"]
        logger.info(f"[x] Your IP: {ip_address}")
        mac_address = ifaddresses(sniffer_interface)[AF_LINK][0]["addr"]
        logger.info(f"[x] Your MAC: {mac_address}")
    except Exception as error:
        logger.exception(
            f"[!] Unable to detect IP or MAC for [{sniffer_interface}] interface, "
            f"current interfaces are [{current_interfaces}]: {error}"
        )
        sys.exit(1)


def _exit_handler():
    logger.info("[x] Cleaning")
    clean_all()
    sleep(1)


class _ArgumentParser(ArgumentParser):
    def error(self, message):
        logger.error(message)
        self.exit(2, f"Error: {message}\n")


def _parse_args() -> tuple[Namespace, dict[str, str | int]]:
    arg_parser = _ArgumentParser(
        description=(
            "Qeeqbox/honeypots customizable honeypots for monitoring network traffic, bots "
            "activities, and username\\password credentials"
        ),
        usage=SUPPRESS,
    )
    arg_parser._action_groups.pop()
    arg_parser_setup = arg_parser.add_argument_group("Arguments")
    arg_parser_setup.add_argument(
        "--setup",
        help="target honeypot E.g. ssh or you can have multiple E.g ssh,http,https",
        metavar="",
        default="",
    )
    arg_parser_setup.add_argument(
        "--list", action="store_true", help="list all available honeypots"
    )
    arg_parser_setup.add_argument("--kill", action="store_true", help="kill all honeypots")
    arg_parser_setup.add_argument("--verbose", action="store_true", help="Print error msgs")
    arg_parser_optional = arg_parser.add_argument_group("Honeypots options")
    arg_parser_optional.add_argument("--ip", help="Override the IP", metavar="", default="")
    arg_parser_optional.add_argument(
        "--port",
        help="Override the Port (Do not use on multiple!)",
        metavar="",
        default="",
    )
    arg_parser_optional.add_argument(
        "--username", help="Override the username", metavar="", default=""
    )
    arg_parser_optional.add_argument(
        "--password", help="Override the password", metavar="", default=""
    )
    arg_parser_optional.add_argument(
        "--config",
        help="Use a config file for honeypots settings",
        metavar="",
        default="",
    )
    arg_parser_optional.add_argument(
        "--options", type=str, help="Extra options", metavar="", default=""
    )
    arg_parser_optional_2 = arg_parser.add_argument_group("General options")
    arg_parser_optional_2.add_argument(
        "--termination-strategy",
        help="Determines the strategy to terminate by",
        default="input",
        choices=["input", "signal"],
    )
    arg_parser_optional_2.add_argument("--test", action="store_true", help="Test a honeypot")
    arg_parser_optional_2.add_argument(
        "--auto", help="Setup the honeypot with random port", action="store_true"
    )
    arg_parser_chameleon = arg_parser.add_argument_group("Chameleon")
    arg_parser_chameleon.add_argument(
        "--chameleon", action="store_true", help="reserved for chameleon project"
    )
    arg_parser_chameleon.add_argument(
        "--sniffer",
        action="store_true",
        help="sniffer - reserved for chameleon project",
    )
    arg_parser_chameleon.add_argument(
        "--iptables",
        action="store_true",
        help="iptables - reserved for chameleon project",
    )
    argv = arg_parser.parse_args()
    server_args = {
        action.dest: getattr(argv, action.dest, "")
        for action in arg_parser_optional._group_actions
    }
    return argv, server_args


def main_logic():
    argv, server_args = _parse_args()
    manager = HoneypotsManager(argv, server_args)
    manager.main()


if __name__ == "__main__":
    main_logic()
