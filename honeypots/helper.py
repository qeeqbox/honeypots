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

from psutil import process_iter
from signal import SIGTERM
from argparse import ArgumentParser
from os import scandir
from socket import socket, AF_INET, SOCK_STREAM
from json import JSONEncoder, dumps, load
from logging import Handler, Formatter
from sys import stdout
from pygments import highlight, lexers, formatters
from datetime import datetime
from logging import DEBUG, getLogger
from logging.handlers import RotatingFileHandler
from tempfile import _get_candidate_names, gettempdir
from os import path, makedirs
from psycopg2 import sql, connect
from sys import stdout
from time import sleep
from traceback import format_exc
from collections import Mapping


def set_local_vars(self, config):
    try:
        honeypot = None
        if config and config != '':
            with open(config) as f:
                config_data = load(f)
                honeypots = config_data['honeypots']
                honeypot = self.__class__.__name__[1:-6].lower()
            if honeypot and honeypot in honeypots:
                for var in honeypots[honeypot]:
                    if var in vars(self):
                        setattr(self, var, honeypots[honeypot][var])
                        if var == "port":
                            setattr(self, "auto_disabled", True)
    except BaseException:
        pass


def get_running_servers():
    temp_list = []
    try:
        honeypots = ['QDNSServer', 'QFTPServer', 'QHTTPProxyServer', 'QHTTPServer', 'QHTTPSServer', 'QIMAPServer', 'QMysqlServer', 'QPOP3Server', 'QPostgresServer', 'QRedisServer', 'QSMBServer', 'QSMTPServer', 'QSOCKS5Server', 'QSSHServer', 'QTelnetServer', 'QVNCServer']
        for process in process_iter():
            cmdline = ' '.join(process.cmdline())
            for honeypot in honeypots:
                if '--custom' in cmdline and honeypot in cmdline:
                    temp_list.append(cmdline.split(" --custom ")[1])
    except BaseException:
        pass
    return temp_list


def disable_logger(logger_type, object):
    if logger_type == 1:
        temp_name = path.join(gettempdir(), next(_get_candidate_names()))
        object.startLogging(open(temp_name, 'w'), setStdout=False)


def setup_logger(temp_name, config, drop=False):
    logs = 'terminal'
    logs_location = ''
    config_data = None
    if config and config != '':
        with open(config) as f:
            config_data = load(f)
            logs = config_data['logs']
            logs_location = config_data['logs_location']
    if logs_location == '' or logs_location is None:
        logs_location = path.join(gettempdir(), 'logs')
    if not path.exists(logs_location):
        makedirs(logs_location)
    file_handler = None
    ret_logs_obj = getLogger(temp_name)
    ret_logs_obj.setLevel(DEBUG)
    if 'terminal' in logs or 'db' in logs or 'all' in logs or logs == '':
        if 'db' in logs or 'all' in logs:
            ret_logs_obj.addHandler(CustomHandler(temp_name, logs, config_data, drop))
        if 'terminal' in logs or 'all' in logs or logs == '':
            ret_logs_obj.addHandler(CustomHandler(temp_name, logs))
    if 'file' in logs or 'all' in logs:
        formatter = Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] - %(message)s')
        file_handler = RotatingFileHandler(path.join(logs_location, temp_name), maxBytes=10000, backupCount=10)
        file_handler.setFormatter(formatter)
        ret_logs_obj.addHandler(file_handler)
    return ret_logs_obj


def clean_all():
    for entry in scandir('.'):
        if entry.is_file() and entry.name.endswith("_server.py"):
            kill_servers(entry.name)


def kill_servers(name):
    try:
        for process in process_iter():
            cmdline = ' '.join(process.cmdline())
            if '--custom' in cmdline and name in cmdline:
                process.send_signal(SIGTERM)
                process.kill()
    except BaseException:
        pass


def kill_server_wrapper(server_name, name, process):
    try:
        if process is not None:
            process.kill()
        for process in process_iter():
            cmdline = ' '.join(process.cmdline())
            if '--custom' in cmdline and name in cmdline:
                process.send_signal(SIGTERM)
                process.kill()
        return True
    except Exception as e:
        pass
    return False


def get_free_port():
    port = 0
    try:
        tcp = socket(AF_INET, SOCK_STREAM)
        tcp.bind(('', 0))
        addr, port = tcp.getsockname()
        tcp.close()
    except BaseException:
        pass
    return port


def close_port_wrapper(server_name, ip, port, logs):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(2)
    if sock.connect_ex((ip, port)) == 0:
        for process in process_iter():
            try:
                for conn in process.connections(kind='inet'):
                    if port == conn.laddr.port:
                        process.send_signal(SIGTERM)
                        process.kill()
            except Exception as e:
                pass
    if sock.connect_ex((ip, port)) != 0:
        return True
    else:
        logs.error(['errors', {'server': server_name, 'error': 'port_open', 'type': 'Port {} still open..'.format(ip)}])
        return False


class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode(errors='replace')
        else:
            return repr(obj)
        return JSONEncoder.default(self, obj)


class ComplexEncoder_db(JSONEncoder):
    def default(self, obj):
        return "Something wrong, deleted.."


def serialize_object(_dict):
    if isinstance(_dict, Mapping):
        return dict((k, serialize_object(v)) for k, v in _dict.items())
    else:
        return repr(_dict)


class CustomHandler(Handler):
    def __init__(self, uuid='', logs='', config=None, drop=False):
        self.db = None
        self.logs = logs
        self.uuid = uuid
        if config and config != '':
            self.db = postgres_class(host=config['host'], port=config['port'], username=config['username'], password=config['password'], db=config['db'], uuid=self.uuid, drop=drop)
        Handler.__init__(self)

    def emit(self, record):
        try:
            if self.logs == 'all' or self.logs == 'db':
                if self.db:
                    self.db.insert_into_data_safe(record.msg[0], dumps(serialize_object(record.msg[1]), cls=ComplexEncoder))
        except Exception as e:
            stdout.write(dumps({"error": repr(e), "logger": repr(record)}, sort_keys=True, cls=ComplexEncoder) + "\n")
        try:
            if self.logs == 'all' or self.logs == '':
                time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if record.msg[0] == "servers":
                    if "server" in record.msg[1]:
                        temp = record.msg[1]
                        action = record.msg[1]['action']
                        server = temp['server'].replace('server', '').replace('_', '')
                        del temp['server']
                        del temp['action']
                        stdout.write("[{}] [{}] [{}] -> {}\n".format(time_now, server, action, dumps(temp, sort_keys=True, cls=ComplexEncoder)))
            else:
                stdout.write(dumps(record.msg, sort_keys=True, cls=ComplexEncoder) + "\n")
        except Exception as e:
            stdout.write(dumps({"error": repr(e), "logger": repr(record)}, sort_keys=True, cls=ComplexEncoder) + "\n")
        stdout.flush()

    def emit_old(self, record):
        try:
            if record.msg[0] == "servers":
                if "server" in record.msg[1]:
                    temp = record.msg[1]
                    server = temp['server']
                    del temp['server']
                    stdout.write(highlight(dumps({server: temp}, sort_keys=True, indent=4, cls=ComplexEncoder), lexers.JsonLexer(), formatters.TerminalFormatter()))
            else:
                stdout.write(highlight(dumps(record.msg, sort_keys=True, indent=4, cls=ComplexEncoder), lexers.JsonLexer(), formatters.TerminalFormatter()))
        except Exception as e:
            stdout.write(highlight(dumps({"error": repr(e), "logger": repr(record)}, sort_keys=True, indent=4, cls=ComplexEncoder), lexers.JsonLexer(), formatters.TerminalFormatter()))
        stdout.flush()


class postgres_class():
    def __init__(self, host=None, port=None, username=None, password=None, db=None, drop=False, uuid=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db
        self.uuid = uuid
        self.mapped_tables = ["errors", "servers", "sniffer", "system"]
        self.wait_until_up()
        if drop:
            self.con = connect(host=self.host, port=self.port, user=self.username, password=self.password)
            self.con.set_isolation_level(0)
            self.cur = self.con.cursor()
            self.drop_db()
            self.drop_tables()
            self.con.close()
        self.con = connect(host=self.host, port=self.port, user=self.username, password=self.password, database=self.db)
        self.con.set_isolation_level(0)
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            try:
                print("{} - Waiting on postgres connection".format(self.uuid))
                stdout.flush()
                conn = connect(host=self.host, port=self.port, user=self.username, password=self.password, connect_timeout=1)
                conn.close()
                test = False
            except Exception as e:
                pass
            sleep(1)
        print("{} - postgres connection is good".format(self.uuid))

    def addattr(self, x, val):
        self.__dict__[x] = val

    def check_db_if_exists(self):
        self.cur.execute("SELECT exists(SELECT 1 from pg_catalog.pg_database where datname = %s)", (self.db,))
        if self.cur.fetchall()[0][0]:
            return True
        else:
            return False

    def drop_db(self):
        try:
            if self.check_db_if_exists():
                self.cur.execute(sql.SQL("drop DATABASE IF EXISTS {}").format(sql.Identifier(self.db)))
                sleep(2)
                self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))
            else:
                self.cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.db)))
        except BaseException:
            pass

    def drop_tables(self,):
        for x in self.mapped_tables:
            self.cur.execute(sql.SQL("drop TABLE IF EXISTS {}").format(sql.Identifier(x + "_table")))

    def create_tables(self):
        for x in self.mapped_tables:
            self.cur.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (id SERIAL NOT NULL,date timestamp with time zone DEFAULT now(),data json)").format(sql.Identifier(x + "_table")))

    def insert_into_data_safe(self, table, obj):
        try:
            # stdout.write(str(table))
            self.cur.execute(
                sql.SQL("INSERT INTO {} (id,date, data) VALUES (DEFAULT ,now(), %s)")
                .format(sql.Identifier(table + "_table")),
                [obj])
            #self.cur.execute(sql.SQL("INSERT INTO errors_table (data) VALUES (%s,)"),dumps(serialize_object(obj),cls=ComplexEncoder))
        except Exception:
            stdout.write(str(format_exc()).replace("\n", " "))
        stdout.flush()


def server_arguments():
    _server_parser = ArgumentParser(prog="Server")
    _server_parsergroupdeq = _server_parser.add_argument_group('Initialize Server')
    _server_parsergroupdeq.add_argument('--ip', type=str, help="Change server ip, current is 0.0.0.0", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--port', type=int, help="Change port", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--username', type=str, help="Change username", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--password', type=str, help="Change password", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--resolver_addresses', type=str, help="Change resolver address", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--domain', type=str, help="A domain to test", required=False, metavar='')
    _server_parsergroupdeq.add_argument('--mocking', type=str, help="Random banner", required=False)
    _server_parsergroupdes = _server_parser.add_argument_group('Sinffer options')
    _server_parsergroupdes.add_argument('--filter', type=str, help="setup the Sinffer filter", required=False)
    _server_parsergroupdes.add_argument('--interface', type=str, help="sinffer interface E.g eth0", required=False)
    _server_parsergroupdef = _server_parser.add_argument_group('Initialize Loging')
    _server_parsergroupdef.add_argument('--config', type=str, help="config file for logs and database", required=False, default="")
    _server_parsergroupdea = _server_parser.add_argument_group('Auto Configuration')
    _server_parsergroupdea.add_argument('--docker', action='store_true', help="Run project in docker", required=False)
    _server_parsergroupdea.add_argument('--aws', action='store_true', help="Run project in aws", required=False)
    _server_parsergroupdea.add_argument('--test', action='store_true', help="Test current server", required=False)
    _server_parsergroupdea.add_argument('--custom', action='store_true', help="Run custom server", required=False)
    _server_parsergroupdea.add_argument('--auto', action='store_true', help="Run auto configured with random port", required=False)
    _server_parsergroupdef.add_argument('--uuid', type=str, help="unique id", required=False)
    return _server_parser.parse_args()
