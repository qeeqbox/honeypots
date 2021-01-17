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

from twisted.conch.telnet import TelnetProtocol, TelnetTransport
from twisted.internet.protocol import Factory
from twisted.internet import reactor
from psutil import process_iter
from signal import SIGTERM
from telnetlib import Telnet as TTelnet
from logging import DEBUG, basicConfig, getLogger
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from os import path

class QTelnetServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 23
		self.username = username or b"test"
		self.password = password or b"password"
		self.mocking = mocking or ''
		self.random_servers = ['Ubuntu 18.04 LTS','Ubuntu 16.04.3 LTS','Welcome to Microsoft Telnet Server.']
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

	def telent_server_main(self):
		_q_s = self

		class CustomTelnetProtocol(TelnetProtocol):
			_state = None
			_user = None
			_pass = None

			def connectionMade(self):
				self._state = None
				self._user = None
				self._pass = None
				self.transport.write(b'PC login: ')
				self._state = b"Username"
				_q_s.logs.info(["servers",{'server':'telnet_server','action':'connection','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port}])

			def dataReceived(self, data):
				data = data.strip()
				if self._state == b'Username':
					self._user = data
					self._state = b"Password"
					self.transport.write(b'Password: ')
				elif self._state == b'Password':
					self._pass = data
					if self._user == _q_s.username and self._pass == _q_s.password:
						_q_s.logs.info(["servers",{'server':'telnet_server','action':'login','status':'success','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':_q_s.username.decode('utf-8'),'password':_q_s.password.decode('utf-8')}])
					else:
						_q_s.logs.info(["servers",{'server':'telnet_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':self._user.decode('utf-8'),'password':self._pass.decode('utf-8')}])
					self.transport.loseConnection()
				else:
					self.transport.loseConnection()

			def connectionLost(self, reason):
				self._state = None
				self._user = None
				self._pass = None

		factory = Factory()
		factory.protocol = lambda: TelnetTransport(CustomTelnetProtocol)
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False):

		if process:
			if self.close_port():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
		else:
			self.telent_server_main()

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
			t = TTelnet(_ip, _port)
			t.read_until(b"login: ")
			t.write(_username + b"\n")
			t.read_until(b"Password: ")
			t.write(_password + b"\n")
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
			self.logs.error(['errors',{'server':'telnet_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	from helper import server_arguments
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qtelnetserver = QTelnetServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		qtelnetserver.run_server()