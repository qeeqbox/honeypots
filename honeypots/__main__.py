#!/usr/bin/env python

from honeypots import clean_all
from time import sleep
from atexit import register
from argparse import ArgumentParser

all_servers = ['QDNSServer', 'QFTPServer', 'QHTTPProxyServer', 'QHTTPServer', 'QHTTPSServer', 'QIMAPServer', 'QMysqlServer', 'QPOP3Server', 'QPostgresServer', 'QRedisServer', 'QSMBServer', 'QSMTPServer', 'QSOCKS5Server', 'QSSHServer', 'QTelnetServer', 'QVNCServer']

temp_honeypots = []


def exit_handler():
    print("Cleaning")
    clean_all()
    sleep(1)


def list_all_honeypots():
    for honeypot in all_servers:
        print(honeypot[1:].replace('Server', '').lower())


def msg():
    '''
    welcome message
    '''

    return """\npython3 -m honeypots --setup all\npython3 -m honeypots --setup ssh --logs all --logs_location /tmp/honeypots_logs\n"""


ARG_PARSER = ArgumentParser(description="Qeeqbox/honeypots customizable honeypots for monitoring network traffic, bots activities, and username\\password credentials", usage=msg())
ARG_PARSER.add_argument("--setup", help="target honeypot E.g. ssh or you can have multiple E.g ssh,http,https", metavar="", default="")
ARG_PARSER.add_argument("--list", action="store_true", help="list all available honeypots")
ARG_PARSER.add_argument("--kill", action="store_true", help="kill all honeypots")
ARG_PARSER.add_argument("--logs", help="terminal, file or all", metavar="", default="terminal")
ARG_PARSER.add_argument("--logs_location", help="logs location", metavar="", default="")
ARGV = ARG_PARSER.parse_args()

if __name__ == "__main__":
    if ARGV.list:
        list_all_honeypots()
    elif ARGV.kill:
        clean_all()
    elif ARGV.setup != "":
        print("Use [Enter] to exit or python3 -m honeypots --kill")
        register(exit_handler)
        if ARGV.setup == "all":
            for honeypot in all_servers:
                x = globals()[honeypot](logs=ARGV.logs, logs_location=ARGV.logs_location)
                x.run_server(process=True, auto=True)
                temp_honeypots.append(x)
        else:
            servers = ARGV.setup.split(',')
            for server in servers:
                if ":" in server:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server.split(':')[0]).lower() == honeypot.lower():
                            x = globals()[honeypot](port=int(server.split(':')[1]), logs=ARGV.logs, logs_location=ARGV.logs_location)
                            x.run_server(process=True)
                            temp_honeypots.append(x)
                else:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server).lower() == honeypot.lower():
                            x = globals()[honeypot](logs=ARGV.logs, logs_location=ARGV.logs_location)
                            x.run_server(process=True, auto=True)
                            temp_honeypots.append(x)
        input("")
        for server in temp_honeypots:
            try:
                print("Killing {}".format(server.__class__.__name__))
                server.kill_server()
            except BaseException:
                pass
        if len(temp_honeypots) > 0:
            print("Please wait few seconds")
            sleep(5)
