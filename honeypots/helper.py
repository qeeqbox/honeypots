from __future__ import annotations

import json
import logging
import os
import sys
from argparse import ArgumentParser
from collections.abc import Mapping
from contextlib import contextmanager, suppress
from datetime import datetime
from json import JSONEncoder
from logging import DEBUG, Formatter, getLogger, Handler, LogRecord
from logging.handlers import RotatingFileHandler, SysLogHandler
from os import getuid, scandir
from pathlib import Path
from signal import SIGTERM
from socket import AF_INET, SOCK_STREAM, socket
from sqlite3 import connect as sqlite3_connect
from sys import stdout
from tempfile import _get_candidate_names, gettempdir, NamedTemporaryFile
from time import sleep, time
from typing import Any, Iterator, MutableMapping
from urllib.parse import urlparse

import psutil
from OpenSSL import crypto
from psutil import process_iter
from psycopg import connect as psycopg_connect, sql

def set_up_error_logging():
    _logger = logging.getLogger("honeypots.error")
    if not _logger.handlers:
        _logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        _logger.addHandler(handler)
    return _logger


logger = set_up_error_logging()


def is_privileged():
    with suppress(Exception):
        return getuid() == 0
    with suppress(Exception):
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return False


def set_local_vars(self, config: str | None = None):
    if not config:
        return
    try:
        config_data = json.loads(Path(config).read_text())
        honeypots = config_data.get("honeypots", [])
        honeypot = self.__class__.__name__[1:-6].lower()
        if honeypot and honeypot in honeypots:
            for attr, value in honeypots[honeypot].items():
                setattr(self, attr, value)
                if attr == "port":
                    self.auto_disabled = True
    except Exception as error:
        logger.debug(f"Setting local variables failed: {error}", exc_info=True)


def _serialize_message(  # noqa: C901
    record: LogRecord,
    custom_filter: dict,
) -> dict | str | None:
    try:
        if custom_filter:
            filters = custom_filter.get("honeypots", {})
            options = filters.get("options", [])
            if "remove_errors" in options and "error" in record.msg:
                return None
            if isinstance(record.msg, MutableMapping):
                if "remove_init" in options and record.msg.get("action") == "process":
                    return None
                if "remove_word_server" in options and "server" in record.msg:
                    record.msg["server"] = record.msg["server"].replace("_server", "")
                for old_key, new_key in filters.get("change", {}).items():
                    if old_key in record.msg:
                        record.msg[new_key] = record.msg.pop(old_key)
                for key in filters.get("remove", []):
                    record.msg.pop(key, None)
                if "contains" in filters and any(k not in record.msg for k in filters["contains"]):
                    return None
        if isinstance(record.msg, Mapping):
            return serialize_object({"timestamp": datetime.utcnow().isoformat(), **record.msg})
        return serialize_object(record.msg)
    except Exception as error:
        return serialize_object({"name": record.name, "error": repr(error)})


def _parse_record(record: LogRecord, custom_filter: dict, type_: str) -> LogRecord | None:
    serialized_msg = _serialize_message(record, custom_filter)
    if not serialized_msg:
        return None
    with suppress(Exception):
        if type_ == "file":
            if custom_filter:
                options = custom_filter.get("honeypots", {}).get("options", [])
                if "dump_json_to_file" in options:
                    record.msg = json.dumps(serialized_msg, sort_keys=True, cls=ComplexEncoder)
        elif type_ == "db_postgres":
            pass
        elif type_ == "db_sqlite":
            for item in ["data", "error"]:
                if item in serialized_msg and not isinstance(serialized_msg[item], str):
                    serialized_msg[item] = repr(serialized_msg[item]).replace("\x00", " ")
        else:
            record.msg = json.dumps(serialized_msg, sort_keys=True, cls=ComplexEncoder)
    return record


def setup_logger(name: str, temp_name: str, config: str | None, drop: bool = False):
    logs = "terminal"
    logs_location = ""
    config_data = {}
    custom_filter = None
    if config:
        try:
            config_data = json.loads(Path(config).read_text())
            logs = config_data.get("logs", logs)
            logs_location = config_data.get("logs_location", logs_location)
            custom_filter = config_data.get("custom_filter", custom_filter)
        except json.JSONDecodeError as error:
            logger.error(f"Could not parse config '{config}' as JSON: {error}")
        except OSError as error:
            logger.error(f"Could not read config file '{config}': {error}")

    logs_path = Path(logs_location) if logs_location else Path(gettempdir()) / "logs"
    logs_path.mkdir(parents=True, exist_ok=True)

    ret_logs_obj = getLogger(temp_name)
    ret_logs_obj.setLevel(DEBUG)
    if "db_postgres" in logs or "db_sqlite" in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter, config_data, drop))
    elif "terminal" in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter))
    if "file" in logs:
        server = name[1:].lower().replace("server", "")
        server_config = config_data.get("honeypots", {}).get(server, {})
        file_handler = CustomHandlerFileRotate(
            str(logs_path / server_config.get("log_file_name", temp_name)),
            logs=logs,
            custom_filter=custom_filter,
            maxBytes=server_config.get("max_bytes", 10000),
            backupCount=server_config.get("backup_count", 10),
        )
        ret_logs_obj.addHandler(file_handler)
    if "syslog" in logs:
        syslog_handler = _set_up_syslog_handler(
            config_data.get("syslog_address"),
            config_data.get("syslog_facility"),
        )
        if syslog_handler:
            ret_logs_obj.addHandler(syslog_handler)
    return ret_logs_obj


def _set_up_syslog_handler(address: str | None, facility: int | None) -> Handler | None:
    if not address:
        address = ("localhost", 514)
    else:
        url = urlparse(address)
        if not url.hostname or not url.port:
            logger.error(f"Could not parse syslog address '{address}': host or port not found")
            return None
        address = (url.hostname, url.port)
    handler = SysLogHandler(address=address, facility=facility)
    formatter = Formatter("[%(name)s] [%(levelname)s] - %(message)s")
    handler.setFormatter(formatter)
    return handler


def clean_all():
    for entry in scandir("."):
        if entry.is_file() and entry.name.endswith("_server.py"):
            kill_servers(entry.name)


def kill_servers(name):
    with suppress(Exception):
        for process in process_iter():
            cmdline = " ".join(process.cmdline())
            if "--custom" in cmdline and name in cmdline:
                process.send_signal(SIGTERM)
                process.kill()


def get_free_port():
    port = 0
    with suppress(Exception):
        tcp = socket(AF_INET, SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        tcp.close()
    return port


class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        return repr(obj).replace("\x00", " ")


def serialize_object(obj: Any) -> dict | list | str:
    if isinstance(obj, Mapping):
        return {k: serialize_object(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [serialize_object(v) for v in obj]
    if isinstance(obj, (int, float)):
        return str(obj)
    if isinstance(obj, bytes):
        obj = obj.decode("utf-8", "ignore")
    elif not isinstance(obj, str):
        obj = repr(obj)
    return obj.replace("\x00", " ")


class CustomHandlerFileRotate(RotatingFileHandler):
    def __init__(self, *args, logs="", custom_filter=None, **kwargs):
        self.logs = logs
        self.custom_filter = custom_filter
        super().__init__(*args, **kwargs)

    def emit(self, record):
        _record = _parse_record(record, self.custom_filter, "file")
        if _record:
            super().emit(_record)


class CustomHandler(Handler):
    def __init__(  # noqa: PLR0913
        self,
        uuid: str = "",
        logs: str = "",
        custom_filter: dict | None = None,
        config: dict | None = None,
        drop: bool = False,
    ):
        self.db = {"db_postgres": None, "db_sqlite": None}
        self.logs = logs
        self.uuid = uuid
        self.custom_filter = custom_filter
        if config and "db_postgres" in self.logs:
            self.db["db_postgres"] = PostgresClass(
                path="postgresql://{}:{}@{}:{}".format(config["postgres"]["username"],config["postgres"]["password"],config["postgres"]["hostname"],config["postgres"]["port"]),
                host=config["postgres"]["hostname"],
                port=config["postgres"]["port"],
                username=config["postgres"]["username"],
                password=config["postgres"]["password"],
                db=config["postgres"]["db"],
                uuid=self.uuid,
                drop=drop,
            )
        if config and "db_sqlite" in self.logs:
            self.db["db_sqlite"] = SqliteClass(
                file=config["sqlite_file"], drop=drop, uuid=self.uuid
            )
        super().__init__()

    def emit(self, record: LogRecord):  # noqa: C901,PLR0912
        try:
            if "db_postgres" in self.logs and self.db["db_postgres"]:
                if isinstance(record.msg, list):
                    if record.msg[0] in {"sniffer", "errors"}:
                        self.db["db_postgres"].insert_into_data_safe(
                            record.msg[0],
                            json.dumps(serialize_object(record.msg[1]), cls=ComplexEncoder),
                        )
                elif isinstance(record.msg, Mapping) and "server" in record.msg:
                    self.db["db_postgres"].insert_into_data_safe(
                        "servers",
                        json.dumps(serialize_object(record.msg), cls=ComplexEncoder),
                    )
            if "db_sqlite" in self.logs:
                _record = _parse_record(record, self.custom_filter, "db_sqlite")
                if _record:
                    self.db["db_sqlite"].insert_into_data_safe(_record.msg)
            if "terminal" in self.logs:
                _record = _parse_record(record, self.custom_filter, "terminal")
                if _record:
                    stdout.write(_record.msg + "\n")
            if "syslog" in self.logs:
                _record = _parse_record(record, self.custom_filter, "terminal")
                if _record:
                    stdout.write(_record.msg + "\n")
        except Exception as error:
            if (
                self.custom_filter is not None
                and "honeypots" in self.custom_filter
                and "remove_errors" in self.custom_filter["honeypots"].get("options", [])
            ):
                return
            log_entry = {"error": repr(error), "logger": repr(record)}
            stdout.write(f"{json.dumps(log_entry, sort_keys=True, cls=ComplexEncoder)}\n")
        stdout.flush()

class PostgresClass:
    def __init__(  # noqa: PLR0913
        self,
        path=None,
        host=None,
        port=None,
        username=None,
        password=None,
        db=None,
        drop=False,
        uuid=None,
    ):
        self.path = path
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db
        self.uuid = uuid
        self.mapped_tables = ["errors", "servers", "sniffer", "system"]
        self.wait_until_up()
        if drop:
            self.con = psycopg_connect(
                conninfo=self.path,
                autocommit=True
            )
            self.cur = self.con.cursor()
            self.drop_db()
            self.drop_tables()
            self.create_db()
            self.con.close()
        else:
            self.con = psycopg_connect(
                conninfo=self.path,
                autocommit=True
            )
            self.cur = self.con.cursor()
            if not self.check_db_if_exists():
                self.create_db()
            self.con.close()
        self.con = psycopg_connect(
                conninfo=self.path + "/" + self.db,
                autocommit=True
        )
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            with suppress():
                logger.info(f"{self.uuid} - Waiting on postgres connection")
                stdout.flush()
                conn = psycopg_connect(
                    conninfo=self.path + "?connect_timeout=1"
                )
                conn.close()
                test = False
            sleep(1)
        logger.info(f"{self.uuid} - postgres connection is good")

    def addattr(self, x, val):
        self.__dict__[x] = val

    def check_db_if_exists(self):
        exists = False
        with suppress(Exception):
            self.cur.execute(
                "SELECT exists(SELECT 1 from pg_catalog.pg_database where datname = %s)",
                (self.db,),
            )
            if self.cur.fetchone()[0]:
                exists = True
        return exists

    def drop_db(self):
        with suppress(Exception):
            logger.warning(f"Dropping {self.db} db")
            if self.check_db_if_exists():
                self.cur.execute(
                    sql.SQL("drop DATABASE IF EXISTS {}").format(sql.Identifier(self.db))
                )
                sleep(2)
            self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))

    def create_db(self):
        logger.info("Creating PostgreSQL database")
        self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))

    def drop_tables(
        self,
    ):
        for x in self.mapped_tables:
            self.cur.execute(
                sql.SQL("drop TABLE IF EXISTS {}").format(sql.Identifier(x + "_table"))
            )

    def create_tables(self):
        for table in self.mapped_tables:
            self.cur.execute(
                sql.SQL(
                    "CREATE TABLE IF NOT EXISTS {} "
                    "(id SERIAL NOT NULL,date timestamp with time zone DEFAULT now(),data json)"
                ).format(sql.Identifier(table + "_table"))
            )

    def insert_into_data_safe(self, table, obj):
        with suppress(Exception):
            self.cur.execute(
                sql.SQL("INSERT INTO {} (id,date, data) VALUES (DEFAULT ,now(), %s)").format(
                    sql.Identifier(table + "_table")
                ),
                [obj],
            )


class SqliteClass:
    def __init__(self, file=None, drop=False, uuid=None):
        self.file = file
        self.uuid = uuid
        self.mapped_tables = ["servers"]
        self.servers_table_template = {
            "server": "servers_table",
            "action": None,
            "status": None,
            "src_ip": None,
            "src_port": None,
            "username": None,
            "password": None,
            "dest_ip": None,
            "dest_port": None,
            "data": None,
            "error": None,
        }
        self.wait_until_up()
        if drop:
            self.con = sqlite3_connect(
                self.file, timeout=1, isolation_level=None, check_same_thread=False
            )
            self.cur = self.con.cursor()
            self.drop_db()
            self.drop_tables()
            self.con.close()
        self.con = sqlite3_connect(
            self.file, timeout=1, isolation_level=None, check_same_thread=False
        )
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            with suppress(Exception):
                logger.info(f"{self.uuid} - Waiting on sqlite connection")
                conn = sqlite3_connect(self.file, timeout=1, check_same_thread=False)
                conn.close()
                test = False
            sleep(1)
        logger.info(f"{self.uuid} - sqlite connection is good")

    def drop_db(self):
        with suppress(Exception):
            file = Path(self.file)
            file.unlink(missing_ok=False)

    def drop_tables(self):
        with suppress(Exception):
            for table in self.mapped_tables:
                self.cur.execute(f"DROP TABLE IF EXISTS '{table:s}'")

    def create_tables(self):
        with suppress(Exception):
            self.cur.execute(
                "CREATE TABLE IF NOT EXISTS 'servers_table' (id INTEGER PRIMARY KEY,"
                "date DATETIME DEFAULT CURRENT_TIMESTAMP,server text, action text, "
                "status text, src_ip text, src_port text,dest_ip text, dest_port text, "
                "username text, password text, data text, error text)"
            )

    def insert_into_data_safe(self, obj):
        with suppress(Exception):
            parsed = {k: v for k, v in obj.items() if v is not None}
            dict_ = {**self.servers_table_template, **parsed}
            if isinstance(dict_.get("data"), dict):
                dict_["data"] = json.dumps(dict_["data"], ensure_ascii=False)
            if isinstance(dict_.get("error"), dict):
                dict_["error"] = json.dumps(dict_["error"], ensure_ascii=False)
            self.cur.execute(
                "INSERT INTO servers_table ("
                "server, action, status, src_ip, src_port, dest_ip, dest_port, username, "
                "password, data, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dict_["server"],
                    dict_["action"],
                    dict_["status"],
                    dict_["src_ip"],
                    dict_["src_port"],
                    dict_["dest_ip"],
                    dict_["dest_port"],
                    dict_["username"],
                    dict_["password"],
                    dict_["data"],
                    dict_["error"],
                ),
            )


def server_arguments():
    _server_parser = ArgumentParser(prog="Server")
    _server_parsergroupdeq = _server_parser.add_argument_group("Initialize Server")
    _server_parsergroupdeq.add_argument(
        "--ip",
        type=str,
        help="Change server ip, current is 0.0.0.0",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--port", type=int, help="Change port", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--username", type=str, help="Change username", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--password", type=str, help="Change password", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--resolver_addresses",
        type=str,
        help="Change resolver address",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--domain", type=str, help="A domain to test", required=False, metavar=""
    )
    _server_parsergroupdeq.add_argument(
        "--folders",
        type=str,
        help="folders for smb as name:target,name:target",
        required=False,
        metavar="",
    )
    _server_parsergroupdeq.add_argument(
        "--options", type=str, help="Extra options", metavar="", default=""
    )
    _server_parsergroupdes = _server_parser.add_argument_group("Sinffer options")
    _server_parsergroupdes.add_argument(
        "--filter", type=str, help="setup the Sinffer filter", required=False
    )
    _server_parsergroupdes.add_argument(
        "--interface", type=str, help="sinffer interface E.g eth0", required=False
    )
    _server_parsergroupdef = _server_parser.add_argument_group("Initialize Loging")
    _server_parsergroupdef.add_argument(
        "--config",
        type=str,
        help="config file for logs and database",
        required=False,
        default="",
    )
    _server_parsergroupdea = _server_parser.add_argument_group("Auto Configuration")
    _server_parsergroupdea.add_argument(
        "--docker", action="store_true", help="Run project in docker", required=False
    )
    _server_parsergroupdea.add_argument(
        "--aws", action="store_true", help="Run project in aws", required=False
    )
    _server_parsergroupdea.add_argument(
        "--test", action="store_true", help="Test current server", required=False
    )
    _server_parsergroupdea.add_argument(
        "--custom", action="store_true", help="Run custom server", required=False
    )
    _server_parsergroupdea.add_argument(
        "--auto",
        action="store_true",
        help="Run auto configured with random port",
        required=False,
    )
    _server_parsergroupdef.add_argument("--uuid", type=str, help="unique id", required=False)
    return _server_parser.parse_args()


@contextmanager
def create_certificate() -> Iterator[tuple[str, str]]:
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)
    certificate = crypto.X509()
    certificate.get_subject().C = "US"
    certificate.get_subject().ST = "OR"
    certificate.get_subject().L = "None"
    certificate.get_subject().O = "None"
    certificate.get_subject().OU = "None"
    certificate.get_subject().CN = next(_get_candidate_names())
    certificate.set_serial_number(0)
    before, after = (0, 60 * 60 * 24 * 365 * 2)
    certificate.gmtime_adj_notBefore(before)
    certificate.gmtime_adj_notAfter(after)
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(pk)
    certificate.sign(pk, "sha256")
    with NamedTemporaryFile() as cert, NamedTemporaryFile() as key:
        cert_path = Path(cert.name)
        key_path = Path(key.name)
        cert_path.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
        key_path.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk))
        yield cert.name, key.name


def check_bytes(string: Any) -> str:
    if isinstance(string, bytes):
        return string.decode("utf-8", errors="replace")
    return str(string)


def load_template(filename: str) -> str:
    file_path = Path(__file__).parent / "data" / filename
    return file_path.read_bytes()


def get_headers_and_ip_from_request(request, options):
    headers = {}
    client_ip = ""
    with suppress(Exception):
        for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
            headers.update({check_bytes(item): ",".join(map(check_bytes, value))})
        headers.update({"method": check_bytes(request.method)})
        headers.update({"uri": check_bytes(request.uri)})
    if "fix_get_client_ip" in options:
        with suppress(Exception):
            raw_headers = dict(request.requestHeaders.getAllRawHeaders())
            if b"X-Forwarded-For" in raw_headers:
                client_ip = check_bytes(raw_headers[b"X-Forwarded-For"][0])
            elif b"X-Real-IP" in raw_headers:
                client_ip = check_bytes(raw_headers[b"X-Real-IP"][0])
    if client_ip == "":
        client_ip = request.getClientAddress().host
    return client_ip, headers


def service_has_started(port: int):
    try:
        wait_for_service(port)
        return True
    except TimeoutError:
        return False


def wait_for_service(port: int, interval: float = 0.1, timeout: int = 5.0):
    start_time = time()
    while True:
        if _service_runs(port):
            return
        sleep(interval)
        if time() - start_time > timeout:
            raise TimeoutError()


def _service_runs(port: int) -> bool:
    return any(service.laddr.port == port for service in psutil.net_connections())


@contextmanager
def hide_stderr():
    stderr = sys.stderr
    try:
        with Path(os.devnull).open("w") as devnull:
            sys.stderr = devnull
            yield
    finally:
        sys.stderr = stderr
