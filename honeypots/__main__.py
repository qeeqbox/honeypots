#!/usr/bin/env python

from sys import argv
from honeypots import QDNSServer, QFTPServer, QHTTPProxyServer, QHTTPServer, QHTTPSServer, QIMAPServer, QMysqlServer, QPOP3Server, QPostgresServer, QRedisServer, QSMBServer, QSMTPServer, QSOCKS5Server, QSSHServer, QTelnetServer, QVNCServer, server_arguments, clean_all
from time import sleep
from atexit import register

all_servers = ['QDNSServer','QFTPServer','QHTTPProxyServer','QHTTPServer','QHTTPSServer','QIMAPServer','QMysqlServer','QPOP3Server','QPostgresServer','QRedisServer','QSMBServer','QSMTPServer','QSOCKS5Server','QSSHServer','QTelnetServer','QVNCServer']

temp_honeypots = []

def exit_handler():
	print("Cleaning...")
	clean_all()

register(exit_handler)

def list_all_honeypots():
	for honeypot in all_servers:
		print(honeypot[1:].replace('Server','').lower())

def main():
	try:
		if argv[1] == "list":
			list_all_honeypots()
		else:
			servers = argv[1].split(',')
			for server in servers:
				for honeypot in all_servers:
					if 'q{}server'.format(server).lower() == honeypot.lower():
						x = globals()[honeypot]()
						x.run_server(process=True,auto=True)
						temp_honeypots.append(x)
			
			wait_on_off = True
			while wait_on_off == True:
				try:
					sleep(60)
				except:
					wait_on_off = False

			print()
			for server in temp_honeypots:
				print("Killing {}".format(server.__class__.__name__))
				server.kill_server()
	except Exception as e:
		print(e)
		pass

if __name__ == "__main__":
	main()
	clean_all()