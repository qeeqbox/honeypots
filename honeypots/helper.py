'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

import sys

from psutil import process_iter
from signal import SIGTERM
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_STREAM
from json import JSONEncoder, dumps, load
from logging import Handler, Formatter, DEBUG, getLogger, addLevelName, INFO
from sys import stdout
from datetime import datetime
from logging.handlers import RotatingFileHandler, SysLogHandler
from tempfile import _get_candidate_names, gettempdir
from os import makedirs, path, scandir, devnull
from psycopg2 import sql, connect
from time import sleep
from traceback import format_exc
from collections.abc import Mapping
from urllib.parse import urlparse

old_stderr = sys.stderr
sys.stderr = open(devnull, 'w')


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
                        if var == 'port':
                            setattr(self, 'auto_disabled', True)
    except Exception as e:
        print(e)


def parse_record(record, custom_filter, type_):
    timestamp = {'timestamp': datetime.utcnow().isoformat()}
    try:
        if custom_filter is not None:
            if 'remove_errors' in custom_filter['honeypots']['options']:
                if 'error' in record.msg:
                    return None
            if isinstance(record.msg, Mapping):
                if 'remove_init' in custom_filter['honeypots']['options']:
                    if record.msg.get('action', None) == 'process':
                        return None
                if 'remove_word_server' in custom_filter['honeypots']['options']:
                    if 'server' in record.msg:
                        record.msg['server'] = record.msg['server'].replace('_server', '')
                if 'honeypots' in custom_filter:
                    for key in record.msg.copy():
                        if key in custom_filter['honeypots']['change']:
                            record.msg[custom_filter['honeypots']['change'][key]] = record.msg.pop(key)
                    for key in record.msg.copy():
                        if key in custom_filter['honeypots']['remove']:
                            del record.msg[key]
                if custom_filter['honeypots']['contains']:
                    if not all(k in record.msg for k in custom_filter['honeypots']['contains']):
                        return None
        if isinstance(record.msg, Mapping):
            record.msg = serialize_object({**timestamp, **record.msg})
        else:
            record.msg = serialize_object(record.msg)
    except Exception as e:
        record.msg = serialize_object({'name': record.name, 'error': repr(e)})
    if type_ == 'file':
        if custom_filter is not None:
            if 'dump_json_to_file' in custom_filter['honeypots']['options']:
                record.msg = dumps(record.msg, sort_keys=True, cls=ComplexEncoder)
    else:
        record.msg = dumps(record.msg, sort_keys=True, cls=ComplexEncoder)
    return record


def get_running_servers():
    temp_list = []
    try:
        honeypots = ['QDNSServer', 'QFTPServer', 'QHTTPProxyServer', 'QHTTPServer', 'QHTTPSServer', 'QIMAPServer', 'QMysqlServer', 'QPOP3Server', 'QPostgresServer', 'QRedisServer', 'QSMBServer', 'QSMTPServer', 'QSOCKS5Server', 'QSSHServer', 'QTelnetServer', 'QVNCServer', 'QElasticServer', 'QMSSQLServer', 'QLDAPServer', 'QNTPServer', 'QMemcacheServer', 'QOracleServer', 'QSNMPServer']
        for process in process_iter():
            cmdline = ' '.join(process.cmdline())
            for honeypot in honeypots:
                if '--custom' in cmdline and honeypot in cmdline:
                    temp_list.append(cmdline.split(' --custom ')[1])
    except BaseException:
        pass
    return temp_list


def disable_logger(logger_type, object):
    if logger_type == 1:
        temp_name = path.join(gettempdir(), next(_get_candidate_names()))
        object.startLogging(open(temp_name, 'w'), setStdout=False)


def setup_logger(name, temp_name, config, drop=False):
    logs = 'terminal'
    logs_location = ''
    syslog_address = ''
    syslog_facility = ''
    config_data = None
    custom_filter = None
    if config and config != '':
        try:
            with open(config) as f:
                config_data = load(f)
                logs = config_data.get('logs', logs)
                logs_location = config_data.get('logs_location', logs_location)
                syslog_address = config_data.get('syslog_address', syslog_address)
                syslog_facility = config_data.get('syslog_facility', syslog_facility)
                custom_filter = config_data.get('custom_filter', custom_filter)
        except BaseException:
            pass
    if logs_location == '' or logs_location is None:
        logs_location = path.join(gettempdir(), 'logs')
    if not path.exists(logs_location):
        makedirs(logs_location)
    file_handler = None
    ret_logs_obj = getLogger(temp_name)
    ret_logs_obj.setLevel(DEBUG)
    if 'db' in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter, config_data, drop))
    elif 'terminal' in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter))
    if 'file' in logs:
        max_bytes = 10000
        backup_count = 10
        try:
            if config_data is not None:
                if 'honeypots' in config_data:
                    temp_server_name = name[1:].lower().replace('server', '')
                    if temp_server_name in config_data['honeypots']:
                        if 'log_file_name' in config_data['honeypots'][temp_server_name]:
                            temp_name = config_data['honeypots'][temp_server_name]['log_file_name']
                        if 'max_bytes' in config_data['honeypots'][temp_server_name]:
                            max_bytes = config_data['honeypots'][temp_server_name]['max_bytes']
                        if 'backup_count' in config_data['honeypots'][temp_server_name]:
                            backup_count = config_data['honeypots'][temp_server_name]['backup_count']
        except Exception as e:
            print(e)
        file_handler = CustomHandlerFileRotate(temp_name, logs, custom_filter, path.join(logs_location, temp_name), maxBytes=max_bytes, backupCount=backup_count)
        ret_logs_obj.addHandler(file_handler)
    if 'syslog' in logs:
        if syslog_address == '':
            address = ('localhost', 514)
        else:
            address = (syslog_address.split('//')[1].split(':')[0], int(syslog_address.split('//')[1].split(':')[1]))
        syslog = SysLogHandler(address=address, facility=syslog_facility)
        formatter = Formatter('[%(name)s] [%(levelname)s] - %(message)s')
        syslog.setFormatter(formatter)
        ret_logs_obj.addHandler(syslog)
    return ret_logs_obj


def clean_all():
    for entry in scandir('.'):
        if entry.is_file() and entry.name.endswith('_server.py'):
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


def check_if_server_is_running(uuid):
    try:
        for process in process_iter():
            cmdline = ' '.join(process.cmdline())
            if '--custom' in cmdline and uuid in cmdline:
                return True
    except BaseException:
        pass

    return False


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
    except Exception:
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
    ret = False
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(2)
    if sock.connect_ex((ip, port)) == 0:
        for process in process_iter():
            try:
                for conn in process.connections(kind='inet'):
                    if port == conn.laddr.port:
                        process.send_signal(SIGTERM)
                        process.kill()
            except Exception:
                pass
    try:
        sock.bind((ip, port))
        ret = True
    except BaseException:
        pass

    if sock.connect_ex((ip, port)) != 0 and ret:
        return True
    else:
        logs.error({'server': server_name, 'error': 'port_open', 'type': 'Port {} still open..'.format(ip)})
        return False


class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        return repr(obj).replace('\x00', ' ')


class ComplexEncoder_db(JSONEncoder):
    def default(self, obj):
        return 'Something wrong, deleted..'


def serialize_object(_dict):
    if isinstance(_dict, Mapping):
        return dict((k, serialize_object(v)) for k, v in _dict.items())
    elif isinstance(_dict, list):
        return list(serialize_object(v) for v in _dict)
    elif isinstance(_dict, (int, float)):
        return str(_dict)
    elif isinstance(_dict, str):
        return _dict.replace('\x00', ' ')
    elif isinstance(_dict, bytes):
        return _dict.decode('utf-8', 'ignore').replace('\x00', ' ')
    else:
        return repr(_dict).replace('\x00', ' ')


class CustomHandlerFileRotate(RotatingFileHandler):
    def __init__(self, uuid='', logs='', custom_filter=None, filename='', mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False, errors=None):
        self.logs = logs
        self.custom_filter = custom_filter
        RotatingFileHandler.__init__(self, filename, mode, maxBytes, backupCount, encoding, delay)

    def emit(self, record):
        _record = parse_record(record, self.custom_filter, 'file')
        if _record is not None:
            super().emit(_record)


class CustomHandler(Handler):
    def __init__(self, uuid='', logs='', custom_filter=None, config=None, drop=False):
        self.db = None
        self.logs = logs
        self.uuid = uuid
        self.custom_filter = custom_filter
        if config and config != '':
            parsed = urlparse(config['postgres'])
            self.db = postgres_class(host=parsed.hostname, port=parsed.port, username=parsed.username, password=parsed.password, db=parsed.path[1:], uuid=self.uuid, drop=drop)
        Handler.__init__(self)

    def emit(self, record):
        try:
            if 'db' in self.logs:
                if self.db:
                    if isinstance(record.msg, list):
                        if record.msg[0] == 'sniffer' or record.msg[0] == 'errors':
                            self.db.insert_into_data_safe(record.msg[0], dumps(serialize_object(record.msg[1]), cls=ComplexEncoder))
                    elif isinstance(record.msg, Mapping):
                        if 'server' in record.msg:
                            self.db.insert_into_data_safe('servers', dumps(serialize_object(record.msg), cls=ComplexEncoder))
            if 'terminal' in self.logs:
                _record = parse_record(record, self.custom_filter,'terminal')
                if _record:
                    stdout.write(_record.msg + '\n')
            if 'syslog' in self.logs:
                _record = parse_record(record, self.custom_filter,'terminal')
                if _record:
                    stdout.write(_record.msg + '\n')
        except Exception as e:
            if self.custom_filter is not None:
                if 'honeypots' in self.custom_filter:
                    if 'remove_errors' in self.custom_filter['honeypots']['options']:
                        return None
            stdout.write(dumps({'error': repr(e), 'logger': repr(record)}, sort_keys=True, cls=ComplexEncoder) + '\n')
        stdout.flush()


class postgres_class():
    def __init__(self, host=None, port=None, username=None, password=None, db=None, drop=False, uuid=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db
        self.uuid = uuid
        self.mapped_tables = ['errors', 'servers', 'sniffer', 'system']
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
        self.con.set_client_encoding('UTF8')
        self.cur = self.con.cursor()
        self.create_tables()

    def wait_until_up(self):
        test = True
        while test:
            try:
                print('{} - Waiting on postgres connection'.format(self.uuid))
                stdout.flush()
                conn = connect(host=self.host, port=self.port, user=self.username, password=self.password, connect_timeout=1)
                conn.close()
                test = False
            except Exception:
                pass
            sleep(1)
        print('{} - postgres connection is good'.format(self.uuid))

    def addattr(self, x, val):
        self.__dict__[x] = val

    def check_db_if_exists(self):
        self.cur.execute('SELECT exists(SELECT 1 from pg_catalog.pg_database where datname = %s)', (self.db,))
        if self.cur.fetchall()[0][0]:
            return True
        else:
            return False

    def drop_db(self):
        try:
            print('[x] Dropping {} db'.format(self.db))
            if self.check_db_if_exists():
                self.cur.execute(sql.SQL('drop DATABASE IF EXISTS {}').format(sql.Identifier(self.db)))
                sleep(2)
            self.cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(self.db)))
        except BaseException:
            pass

    def drop_tables(self,):
        for x in self.mapped_tables:
            self.cur.execute(sql.SQL('drop TABLE IF EXISTS {}').format(sql.Identifier(x + '_table')))

    def create_tables(self):
        for x in self.mapped_tables:
            self.cur.execute(sql.SQL('CREATE TABLE IF NOT EXISTS {} (id SERIAL NOT NULL,date timestamp with time zone DEFAULT now(),data json)').format(sql.Identifier(x + '_table')))

    def insert_into_data_safe(self, table, obj):
        try:
            # stdout.write(str(table))
            self.cur.execute(
                sql.SQL('INSERT INTO {} (id,date, data) VALUES (DEFAULT ,now(), %s)')
                .format(sql.Identifier(table + '_table')),
                [obj])
            #self.cur.execute(sql.SQL('INSERT INTO errors_table (data) VALUES (%s,)'),dumps(serialize_object(obj),cls=ComplexEncoder))
        except Exception:
            stdout.write(str(format_exc()).replace('\n', ' '))
        stdout.flush()


def server_arguments():
    _server_parser = ArgumentParser(prog='Server')
    _server_parsergroupdeq = _server_parser.add_argument_group('Initialize Server')
    _server_parsergroupdeq.add_argument('--ip', type=str, help='Change server ip, current is 0.0.0.0', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--port', type=int, help='Change port', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--username', type=str, help='Change username', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--password', type=str, help='Change password', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--resolver_addresses', type=str, help='Change resolver address', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--domain', type=str, help='A domain to test', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--folders', type=str, help='folders for smb as name:target,name:target', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--mocking', type=str, help='Random banner', required=False)
    _server_parsergroupdes = _server_parser.add_argument_group('Sinffer options')
    _server_parsergroupdes.add_argument('--filter', type=str, help='setup the Sinffer filter', required=False)
    _server_parsergroupdes.add_argument('--interface', type=str, help='sinffer interface E.g eth0', required=False)
    _server_parsergroupdef = _server_parser.add_argument_group('Initialize Loging')
    _server_parsergroupdef.add_argument('--config', type=str, help='config file for logs and database', required=False, default='')
    _server_parsergroupdea = _server_parser.add_argument_group('Auto Configuration')
    _server_parsergroupdea.add_argument('--docker', action='store_true', help='Run project in docker', required=False)
    _server_parsergroupdea.add_argument('--aws', action='store_true', help='Run project in aws', required=False)
    _server_parsergroupdea.add_argument('--test', action='store_true', help='Test current server', required=False)
    _server_parsergroupdea.add_argument('--custom', action='store_true', help='Run custom server', required=False)
    _server_parsergroupdea.add_argument('--auto', action='store_true', help='Run auto configured with random port', required=False)
    _server_parsergroupdef.add_argument('--uuid', type=str, help='unique id', required=False)
    return _server_parser.parse_args()
