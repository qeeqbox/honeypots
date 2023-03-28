#!/usr/bin/env python

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')
filterwarnings('ignore', category=RuntimeWarning, module='runpy')

all_servers = ['QDNSServer', 'QFTPServer', 'QHTTPProxyServer', 'QHTTPServer', 'QHTTPSServer', 'QIMAPServer', 'QMysqlServer', 'QPOP3Server', 'QPostgresServer', 'QRedisServer', 'QSMBServer', 'QSMTPServer', 'QSOCKS5Server', 'QSSHServer', 'QTelnetServer', 'QVNCServer', 'QElasticServer', 'QMSSQLServer', 'QLDAPServer', 'QNTPServer', 'QMemcacheServer', 'QOracleServer', 'QSNMPServer', 'QSIPServer', 'QIRCServer', 'QRDPServer', 'QDHCPServer', 'QPJLServer', 'QIPPServer']
temp_honeypots = []

from signal import signal, alarm, SIGALRM, SIG_IGN, SIGTERM, SIGINT, SIGTSTP
from time import sleep
from functools import wraps


class SignalFence:
    def __init__(self, signals_to_listen_on, interval=1):
        self.fence_up = True
        self.interval = interval

        for signal_to_listen_on in signals_to_listen_on:
            signal(signal_to_listen_on, self.handle_signal)

    def handle_signal(self, signum, frame):
        self.fence_up = False

    def wait_on_fence(self):
        while self.fence_up:
            sleep(self.interval)


class Termination:
    def __init__(self, strategy):
        self.strategy = strategy

    def await_termination(self):
        if self.strategy == 'input':
            input('')
        elif self.strategy == 'signal':
            SignalFence([SIGTERM, SIGINT, SIGTSTP]).wait_on_fence()
        else:
            raise Exception('Unknown termination strategy: ' + strategy)


def timeout(seconds=10):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def handle_timeout(signum, frame):
                raise Exception()
            signal(SIGALRM, handle_timeout)
            alarm(seconds)
            result = None
            try:
                result = func(*args, **kwargs)
            finally:
                alarm(0)
            return result
        return wrapper
    return decorator


def list_all_honeypots():
    for honeypot in all_servers:
        print(honeypot[1:].replace('Server', '').lower())


@timeout(5)
def server_timeout(object, name):
    try:
        print('[x] Start testing {}'.format(name))
        object.test_server()
    except BaseException:
        print('[x] Timeout {}'.format(name))
    print('[x] Done testing {}'.format(name))


def main_logic():

    from honeypots import QDNSServer, QFTPServer, QHTTPProxyServer, QHTTPServer, QHTTPSServer, QIMAPServer, QMysqlServer, QPOP3Server, QPostgresServer, QRedisServer, QSMBServer, QSMTPServer, QSOCKS5Server, QSSHServer, QTelnetServer, QVNCServer, QMSSQLServer, QElasticServer, QLDAPServer, QNTPServer, QMemcacheServer, QOracleServer, QSNMPServer, QSIPServer, QIRCServer, QRDPServer, QDHCPServer, QPJLServer, QIPPServer, server_arguments, clean_all, postgres_class, setup_logger, QBSniffer, get_running_servers, check_privileges
    from atexit import register
    from argparse import ArgumentParser, SUPPRESS
    from sys import stdout
    from subprocess import Popen
    from netifaces import ifaddresses, AF_INET, AF_LINK, interfaces
    from psutil import Process, net_io_counters
    from uuid import uuid4
    from json import JSONEncoder, dumps, load
    from os import geteuid

    def exit_handler():
        print('[x] Cleaning')
        clean_all()
        sleep(1)

    class _ArgumentParser(ArgumentParser):
        def error(self, message):
            self.exit(2, 'Error: %s\n' % (message))

    ARG_PARSER = _ArgumentParser(description='Qeeqbox/honeypots customizable honeypots for monitoring network traffic, bots activities, and username\\password credentials', usage=SUPPRESS)
    ARG_PARSER._action_groups.pop()
    ARG_PARSER_SETUP = ARG_PARSER.add_argument_group('Arguments')
    ARG_PARSER_SETUP.add_argument('--setup', help='target honeypot E.g. ssh or you can have multiple E.g ssh,http,https', metavar='', default='')
    ARG_PARSER_SETUP.add_argument('--list', action='store_true', help='list all available honeypots')
    ARG_PARSER_SETUP.add_argument('--kill', action='store_true', help='kill all honeypots')
    ARG_PARSER_SETUP.add_argument('--verbose', action='store_true', help='Print error msgs')
    ARG_PARSER_OPTIONAL = ARG_PARSER.add_argument_group('Honeypots options')
    ARG_PARSER_OPTIONAL.add_argument('--ip', help='Override the IP', metavar='', default='')
    ARG_PARSER_OPTIONAL.add_argument('--port', help='Override the Port (Do not use on multiple!)', metavar='', default='')
    ARG_PARSER_OPTIONAL.add_argument('--username', help='Override the username', metavar='', default='')
    ARG_PARSER_OPTIONAL.add_argument('--password', help='Override the password', metavar='', default='')
    ARG_PARSER_OPTIONAL.add_argument('--config', help='Use a config file for honeypots settings', metavar='', default='')
    ARG_PARSER_OPTIONAL.add_argument('--options', type=str, help='Extra options', metavar='', default='')
    ARG_PARSER_OPTIONAL_2 = ARG_PARSER.add_argument_group('General options')
    ARG_PARSER_OPTIONAL_2.add_argument('--termination-strategy', help='Determines the strategy to terminate by', default='input', choices=['input', 'signal'])
    ARG_PARSER_OPTIONAL_2.add_argument('--test', default='', metavar='', help='Test a honeypot')
    ARG_PARSER_OPTIONAL_2.add_argument('--auto', help='Setup the honeypot with random port', action='store_true')
    ARG_PARSER_CHAMELEON = ARG_PARSER.add_argument_group('Chameleon')
    ARG_PARSER_CHAMELEON.add_argument('--chameleon', action='store_true', help='reserved for chameleon project')
    ARG_PARSER_CHAMELEON.add_argument('--sniffer', action='store_true', help='sniffer - reserved for chameleon project')
    ARG_PARSER_CHAMELEON.add_argument('--iptables', action='store_true', help='iptables - reserved for chameleon project')
    ARGV = ARG_PARSER.parse_args()
    PARSED_ARG_PARSER_OPTIONAL = {action.dest: getattr(ARGV, action.dest, '') for action in ARG_PARSER_OPTIONAL._group_actions}
    config_data = None
    print("[!] For updates, check https://github.com/qeeqbox/honeypots")
    if check_privileges() == False:
        print("[!] Using system or well-known ports requires higher privileges (E.g. sudo -E)")
    if ARGV.config != '':
        with open(ARGV.config) as f:
            try:
                config_data = load(f)
            except Exception as e:
                print('[!] Unable to load or parse config.json file', e)
                exit()
            if 'db_sqlite' in config_data['logs'] or 'db_postgres' in config_data['logs']:
                uuid = 'honeypotslogger' + '_' + 'main' + '_' + str(uuid4())[:8]
                if 'db_options' in config_data:
                    if 'drop' in config_data['db_options']:
                        print('[x] Setup Logger {} with a db, drop is on'.format(uuid))
                        logs = setup_logger('main', uuid, ARGV.config, True)
                    else:
                        print('[x] Setup Logger {} with a db, drop is off'.format(uuid))
                        logs = setup_logger('main', uuid, ARGV.config, False)
                else:
                    logs = setup_logger('main', uuid, ARGV.config, True)
    if ARGV.list:
        list_all_honeypots()
    elif ARGV.kill:
        clean_all()
    elif ARGV.chameleon and config_data is not None:
        print('[x] Chameleon mode')
        if config_data['sniffer_filter'] and config_data['sniffer_interface']:
            if not ARGV.test:
                if ARGV.sniffer:
                    current_interfaces = 'unknown'
                    try:
                        current_interfaces = ' '.join(interfaces())
                        if config_data['sniffer_interface'] in current_interfaces:
                            print('[x] Your IP: {}'.format(ifaddresses(config_data['sniffer_interface'])[AF_INET][0]['addr']))
                            print('[x] Your MAC: {}'.format(ifaddresses(config_data['sniffer_interface'])[AF_LINK][0]['addr']))
                        else:
                            exit()
                    except Exception as e:
                        print('[!] Unable to detect IP or MAC for [{}] interface, current interfaces are [{}]'.format(config_data['sniffer_interface'], current_interfaces), e)
                        exit()
                    if ARGV.iptables:
                        try:
                            print('[x] Fixing iptables')
                            Popen('iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP', shell=True)
                        except Exception as e:
                            print(e)
                    print('[x] Wait for 10 seconds..')
                    stdout.flush()
                    sleep(2)

            if ARGV.config != '':
                print('[x] Config.json file overrides --ip, --port, --username and --password')

            if isinstance(config_data['honeypots'], dict):
                print('[x] Parsing honeypot [hard]')
                for honeypot in config_data['honeypots']:
                    for _honeypot in all_servers:
                        if 'q{}server'.format(honeypot).lower() == _honeypot.lower():
                            if ARGV.port != '':
                                ARGV.port = int(ARGV.port)
                            PARSED_ARG_PARSER_OPTIONAL['port'] = ARGV.port
                            x = locals()[_honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                            if not ARGV.test:
                                x.run_server(process=True)
                            else:
                                server_timeout(x, _honeypot)
                                x.kill_server()
                            temp_honeypots.append(x)
            elif isinstance(config_data['honeypots'], str):
                print('[x] Parsing honeypot [easy]')
                if ':' in config_data['honeypots']:
                    print('[!] You cannot bind ports with [:] in this mode, use the honeypots dict instead')
                    exit()
                for server in config_data['honeypots'].split(','):
                    for honeypot in all_servers:
                        if 'q{}server'.format(server).lower() == honeypot.lower():
                            if ARGV.port != '':
                                ARGV.port = int(ARGV.port)
                            PARSED_ARG_PARSER_OPTIONAL['port'] = ARGV.port
                            x = locals()[honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                            if not ARGV.test:
                                x.run_server(process=True)
                            else:
                                server_timeout(x, honeypot)
                                x.kill_server()
                            temp_honeypots.append(x)
            else:
                print('[!] Unable to parse honeypot from config.json file')
                exit()

            if ARGV.sniffer:
                print('[x] Start sniffer')
                x = locals()['QBSniffer'](filter=config_data['sniffer_filter'], interface=config_data['sniffer_interface'], config=ARGV.config)
                x.run_sniffer(process=True)
                temp_honeypots.append(x)

            if not ARGV.test:
                print('[x] Everything looks good!')
                while True:
                    try:
                        _servers = {}
                        logs.info(['system', {'type': 'network', 'bytes_sent': net_io_counters().bytes_sent, 'bytes_recv': net_io_counters().bytes_recv, 'packets_sent': net_io_counters().packets_sent, 'packets_recv': net_io_counters().packets_recv}])
                        for server in temp_honeypots:
                            _servers[server.__class__.__name__] = {'memory': Process(server.process.pid).memory_percent(), 'cpu': Process(server.process.pid).cpu_percent()}
                        logs.info(['system', _servers])
                    except Exception as e:
                        print(e)
                    sleep(20)
            else:
                if len(temp_honeypots) > 0:
                    for server in temp_honeypots:
                        try:
                            print('[x] Killing {} tester'.format(server.__class__.__name__))
                            server.kill_server()
                        except Exception as e:
                            print(e)
                    print('[x] Please wait few seconds')
                    sleep(5)
    elif ARGV.setup != '':

        register(exit_handler)
        auto = ARGV.auto
        if ARGV.termination_strategy == 'input':
            print('[x] Use [Enter] to exit or python3 -m honeypots --kill')

        if ARGV.config != '':
            print('[x] config.json file overrides --ip, --port, --username and --password')

        if geteuid() == 0:
            auto = False

        if ARGV.setup == 'all':
            try:
                for honeypot in all_servers:
                    status = False
                    x = locals()[honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                    status = x.run_server(process=True, auto=auto)
                    temp_honeypots.append([x, honeypot, status])
            except Exception as e:
                print(e)
        else:
            servers = ARGV.setup.split(',')
            for server in servers:
                print('[x] Parsing honeypot [normal]')
                if ':' in server:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server.split(':')[0]).lower() == honeypot.lower():
                            ARGV.port = int(server.split(':')[1])
                            PARSED_ARG_PARSER_OPTIONAL['port'] = ARGV.port
                            x = locals()[honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                            status = False
                            if not ARGV.test:
                                status = x.run_server(process=True)
                            else:
                                server_timeout(x, honeypot)
                                x.kill_server()
                            temp_honeypots.append([x, honeypot, status])
                elif ARGV.port != '':
                    for honeypot in all_servers:
                        if 'q{}server'.format(server).lower() == honeypot.lower():
                            x = locals()[honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                            status = False
                            if not ARGV.test:
                                status = x.run_server(process=True)
                            else:
                                server_timeout(x, honeypot)
                                x.kill_server()
                            temp_honeypots.append([x, honeypot, status])
                else:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server).lower() == honeypot.lower():
                            x = locals()[honeypot](**PARSED_ARG_PARSER_OPTIONAL)
                            status = False
                            if not ARGV.test:
                                status = x.run_server(process=True, auto=auto)
                            else:
                                print('[x] {} was configured with random port, unable to test..'.format(honeypot))
                            temp_honeypots.append([x, honeypot, status])

        running_honeypots = {'good': [], 'bad': []}

        if len(temp_honeypots) > 0:
            good = True
            for server in temp_honeypots:
                if server[2] == False or server[2] is None:
                    running_honeypots['bad'].append(server[1])
                else:
                    running_honeypots['good'].append(server[1])

            if len(running_honeypots['good']) > 0:
                print('[x] {} running..'.format(', '.join(running_honeypots['good'])))

            if len(running_honeypots['bad']) > 0:
                print('[x] {} not running..'.format(', '.join(running_honeypots['bad'])))

            if len(running_honeypots['bad']) == 0:
                print('[x] Everything looks good!')

            if len(running_honeypots['good']) > 0:
                if not ARGV.test:
                    Termination(ARGV.termination_strategy).await_termination()

            for server in temp_honeypots:
                try:
                    if not ARGV.test:
                        print('[x] Killing {} honeypot'.format(server[0].__class__.__name__))
                    else:
                        print('[x] Killing {} tester'.format(server[0].__class__.__name__))
                    server[0].kill_server()
                except Exception as e:
                    print(e)
            print('[x] Please wait few seconds')
            sleep(5)


if __name__ == '__main__':
    main_logic()
