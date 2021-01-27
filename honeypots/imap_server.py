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

from twisted.mail.imap4 import IMAP4Server
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from random import choice
from psutil import process_iter
from signal import SIGTERM
from logging import DEBUG, basicConfig, getLogger
from twisted import cred
from imaplib import IMAP4
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from os import path
from honeypots.helper import server_arguments, get_free_port, CustomHandler
from uuid import uuid4

class QIMAPServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 143
		self.username = username or "test"
		self.password = password or "test"
		self.mocking = mocking or ''
		self.random_servers = [b'OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.6944.0 DC9 ready']
		self.process = None
		self._logs = logs
		self.setup_logger(self._logs)
		#self.disable_logger()

	def disable_logger(self):
		temp_name = path.join(gettempdir(), next(_get_candidate_names()))
		tlog.startLogging(open(temp_name, 'w'), setStdout=False)

	def setup_logger(self,logs):
		self.logs = getLogger('honeypotslogger'+'_'+__class__.__name__+'_'+str(uuid4())[:8])
		self.logs.setLevel(DEBUG)
		self.logs.addHandler(CustomHandler())

	def imap_server_main(self):

		_q_s = self

		class CustomIMAP4Server(IMAP4Server):

			def connectionMade(self):
				_q_s.logs.info(["servers",{'server':'imap_server','action':'connection','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port}])

				if isinstance(_q_s.mocking, bool):
					if _q_s.mocking == True:
						self.sendPositiveResponse(message=choice(_q_s.random_servers))
				elif isinstance(_q_s.mocking, str):
					self.sendPositiveResponse(message=choice(_q_s.random_servers))
				else:
					self.sendPositiveResponse(message=b'Welcome')

			def authenticateLogin(self, user, passwd):
				if user == _q_s.username and passwd == _q_s.password:
					_q_s.logs.info(["servers",{'server':'imap_server','action':'login','status':'success','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':_q_s.username,'password':_q_s.password}])
				else:
					_q_s.logs.info(["servers",{'server':'imap_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':user,'password':passwd}])
				
				raise cred.error.UnauthorizedLogin()

			def lineReceived(self, line):
				try:
					_line = line.split(b" ")[1]
					if _line.lower().startswith(b"login") or _line.lower().startswith(b"capability"):
						IMAP4Server.lineReceived(self, line)
				except:
					pass

		class CustomIMAPFactory(Factory):
			protocol = CustomIMAP4Server
			portal = None
			
			def buildProtocol(self, address):
				p = self.protocol()
				p.portal = self.portal
				p.factory = self
				return p

		factory = CustomIMAPFactory()
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False,auto=False):
		if process:
			if auto:
				port = get_free_port()
				if port > 0:
					self.port = port
					self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
					if self.process.poll() is None:
						self.logs.info(["servers",{'server':'imap_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
					else:
						self.logs.info(["servers",{'server':'imap_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'imap_server','action':'setup','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
			elif self.close_port() and self.kill_server():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
				if self.process.poll() is None:
					self.logs.info(["servers",{'server':'imap_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'imap_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
		else:
			self.imap_server_main()

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

	def test_server(self,ip=None,port=None,username=None,password=None):
		try:
			_ip = ip or self.ip
			_port = port or self.port 
			_username = username or self.username
			_password = password or self.password
			imap_test = IMAP4(_ip,_port)
			imap_test.login(_username, _password)
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
			self.logs.error(['errors',{'server':'imap_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qimapserver = QIMAPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		qimapserver.run_server()