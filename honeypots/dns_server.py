"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/social-analyzer/graphs/contributors
//  -------------------------------------------------------------
"""

from warnings import filterwarnings
filterwarnings(action='ignore',module='.*OpenSSL.*')

from twisted.names import dns, error,client
from twisted.names.server import DNSServerFactory
from twisted.internet import defer, reactor
from psutil import process_iter
from signal import SIGTERM
from time import sleep
from subprocess import Popen,PIPE
from shlex import split as ssplit
from logging import DEBUG, basicConfig, getLogger
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from os import path
from dns.resolver import Resolver

class QDNSServer():
	def __init__(self,ip=None,port=None,resolver_addresses=None,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 53
		self.resolver_addresses = resolver_addresses or [('8.8.8.8', 53)]
		self.process = None
		self._logs = logs
		self.setup_logger(self._logs)
		self.disable_logger()

	def disable_logger(self):
		temp_name = path.join(gettempdir(), next(_get_candidate_names()))
		tlog.startLogging(open(temp_name, 'w'), setStdout=False)

	def setup_logger(self,logs):
		self.logs = getLogger('honeypotslogger')
		self.logs.setLevel(DEBUG)
		basicConfig()

	def dns_server_main(self):
		_q_s = self

		class CustomCilentResolver(client.Resolver):
			def queryUDP(self, queries, timeout=2):
				res = client.Resolver.queryUDP(self, queries, timeout)
				def queryFailed(reason):
					return defer.fail(error.DomainError())
				res.addErrback(queryFailed)
				return res

		class CustomDNSServerFactory(DNSServerFactory):
			def gotResolverResponse(self, response, protocol, message, address):
				args = (self, response, protocol, message, address)
				_q_s.logs.info(['servers',{'server':'dns_server','action':'connection','ip':address[0],'port':address[1]}])
				try:
					for items in response:
						for item in items:
							_q_s.logs.info(['servers',{'server':'dns_server','action':'query','ip':address[0],'port':address[1],'payload':item.payload}])
				except Exception as e:
					_q_s.logs.error(['errors',{'server':'dns_server','error':'gotResolverResponse','type':'error -> '+repr(e)}])
				return DNSServerFactory.gotResolverResponse(*args)


		self.resolver = CustomCilentResolver(servers=self.resolver_addresses)
		self.factory = CustomDNSServerFactory(clients=[self.resolver])
		self.protocol = dns.DNSDatagramProtocol(controller=self.factory)
		reactor.listenUDP(self.port, self.protocol,interface=self.ip)
		reactor.listenTCP(self.port, self.factory,interface=self.ip)
		reactor.run()

	def run_server(self,process=False):
		if process:
			if self.close_port():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--logs',str(self._logs)])
		else:
			self.dns_server_main()

	def kill_server(self,process=False):
		try:
			
			for process in process_iter():
				cmdline = ' '.join(process.cmdline())
				if '--custom' in cmdline and Path(__file__).name in cmdline:
					process.send_signal(SIGTERM)
					process.kill()
			if self.process != None:
				self.process.kill()
		except:
			pass

	def test_server(self,ip=None,port=None,domain=None):
		try:
			res = Resolver(configure=False)
			res.nameservers = [self.ip]
			res.port = self.port
			temp_domain = domain or "example.org"
			r = res.query(temp_domain, 'a')
		except:
			pass

	def close_port(self):
		sock = ssocket(AF_INET,SOCK_STREAM)
		sock.settimeout(2)
		if sock.connect_ex((self.ip,self.port)) == 0:
			for process in process_iter():
				try:
					for conn in process.connections(kind='inet'):
						if self.port == conn.laddr.port:
							process.send_signal(SIGTERM)
							process.kill()
				except:
					pass
		if sock.connect_ex((self.ip,self.port)) != 0:
			return True
		else:
			self.logs.error(['errors',{'server':'dns_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	from helper import server_arguments
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qdnsserver = QDNSServer(ip=parsed.ip,port=parsed.port,resolver_addresses=parsed.resolver_addresses,logs=parsed.logs)
		qdnsserver.run_server()
