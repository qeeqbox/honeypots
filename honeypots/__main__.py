#!/usr/bin/env python

from sys import argv
from honeypots import QDNSServer, QFTPServer, QHTTPProxyServer, QHTTPServer, QHTTPSServer, QIMAPServer, QMysqlServer, QPOP3Server, QPostgresServer, QRedisServer, QSMBServer, QSMTPServer, QSOCKS5Server, QSSHServer, QTelnetServer, QVNCServer, server_arguments, clean_all
from time import sleep
from atexit import register

all_servers = ['QDNSServer', 'QFTPServer', 'QHTTPProxyServer', 'QHTTPServer', 'QHTTPSServer', 'QIMAPServer', 'QMysqlServer', 'QPOP3Server', 'QPostgresServer', 'QRedisServer', 'QSMBServer', 'QSMTPServer', 'QSOCKS5Server', 'QSSHServer', 'QTelnetServer', 'QVNCServer']

temp_honeypots = []


def exit_handler():
    print("Cleaning")
    clean_all()
    sleep(5)


register(exit_handler)


def list_all_honeypots():
    for honeypot in all_servers:
        print(honeypot[1:].replace('Server', '').lower())


def main():
    print("\nUse enter to exit\n")
    try:
        if argv[1] == "list":
            list_all_honeypots()
        elif argv[1] == "all":
            for honeypot in all_servers:
                x = globals()[honeypot]()
                x.run_server(process=True, auto=True)
                temp_honeypots.append(x)
        else:
            servers = argv[1].split(',')
            for server in servers:
                if ":" in server:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server.split(':')[0]).lower() == honeypot.lower():
                            x = globals()[honeypot](port=int(server.split(':')[1]))
                            x.run_server(process=True)
                            temp_honeypots.append(x)
                else:
                    for honeypot in all_servers:
                        if 'q{}server'.format(server).lower() == honeypot.lower():
                            x = globals()[honeypot]()
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
    except Exception as e:
        pass


if __name__ == "__main__":
    main()
    clean_all()
