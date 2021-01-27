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

from dns.resolver import query as dsnquery
from twisted.internet import reactor
from twisted.internet.protocol import Protocol,ClientFactory,Factory
from psutil import process_iter
from signal import SIGTERM
from requests import get
from logging import DEBUG, basicConfig, getLogger
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from email.parser import BytesParser
from pathlib import Path
from os import path
from honeypots.helper import server_arguments, get_free_port, CustomHandler
from uuid import uuid4

class QHTTPProxyServer():
	def __init__(self,ip=None,port=None,mocking=None,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 8080 
		self.mocking = mocking or ''
		self.process = None
		self._logs = logs
		self.setup_logger(self._logs)
		self.disable_logger()

	def disable_logger(self):
		temp_name = path.join(gettempdir(), next(_get_candidate_names()))
		tlog.startLogging(open(temp_name, 'w'), setStdout=False)

	def setup_logger(self,logs):
		self.logs = getLogger('honeypotslogger'+'_'+__class__.__name__+'_'+str(uuid4())[:8])
		self.logs.setLevel(DEBUG)
		self.logs.addHandler(CustomHandler())

	def http_proxy_server_main(self):
		_q_s = self

		class CustomProtocolParent(Protocol):

			def __init__(self):
				self.buffer = None
				self.client = None

			def resolve_domain(self,request_string):
				try:
					_, parsed_request = request_string.split(b'\r\n', 1)
					headers = BytesParser().parsebytes(parsed_request)
					host = headers["host"].split(":")
					_q_s.logs.info(["servers",{'server':'http_proxy_server','action':'query','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'payload':host[0]}])
					#return "127.0.0.1"
					return dsnquery(host[0], 'A')[0].address
				except Exception as e:
					_q_s.logs.error(["errors",{'server':'http_proxy_server','error':'resolve_domain',"type":"error -> "+repr(e)}])
				return None

			def dataReceived(self, data):
				_q_s.logs.info(["servers",{'server':'http_proxy_server','action':'connection','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port}])
				try:
					ip = self.resolve_domain(data)
					if ip:
						factory = ClientFactory()
						factory.CustomProtocolParent_= self
						factory.protocol = CustomProtocolChild
						reactor.connectTCP(ip, 80, factory)
					else:
						self.transport.loseConnection()

					if self.client:
						self.client.write(data)
					else:
						self.buffer = data
				except:
					pass

			def write(self, data):
				self.transport.write(data)

		class CustomProtocolChild(Protocol):
			def connectionMade(self):
				self.write(self.factory.CustomProtocolParent_.buffer)

			def dataReceived(self, data):
				self.factory.CustomProtocolParent_.write(data)

			def write(self, data):
				self.transport.write(data)

		factory = Factory()
		factory.protocol = CustomProtocolParent
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False,auto=False):
		if process:
			if auto:
				port = get_free_port()
				if port > 0:
					self.port = port
					self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--mocking',str(self.mocking),'--logs',str(self._logs)])
					if self.process.poll() is None:
						self.logs.info(["servers",{'server':'http_proxy_server','action':'process','status':'success','ip':self.ip,'port':self.port}])
					else:
						self.logs.info(["servers",{'server':'http_proxy_server','action':'process','status':'error','ip':self.ip,'port':self.port}])
				else:
					self.logs.info(["servers",{'server':'http_proxy_server','action':'setup','status':'error','ip':self.ip,'port':self.port}])
			elif self.close_port() and self.kill_server():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--mocking',str(self.mocking),'--logs',str(self._logs)])
				if self.process.poll() is None:
					self.logs.info(["servers",{'server':'http_proxy_server','action':'process','status':'success','ip':self.ip,'port':self.port}])
				else:
					self.logs.info(["servers",{'server':'http_proxy_server','action':'process','status':'error','ip':self.ip,'port':self.port}])
		else:
			self.http_proxy_server_main()

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
			_ip = ip or self.ip
			_port = port or self.port
			_domain = domain or "http://yahoo.com"
			get(_domain, proxies={"http":'http://{}:{}'.format(_ip,_port)}).text.encode('ascii', 'ignore')
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
			self.logs.error(['errors',{'server':'http_proxy_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qhttpproxyserver = QHTTPProxyServer(ip=parsed.ip,port=parsed.port,mocking=parsed.mocking,logs=parsed.logs)
		qhttpproxyserver.run_server()