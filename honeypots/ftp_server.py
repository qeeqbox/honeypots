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

from twisted.protocols.ftp import FTPFactory, FTP, AUTH_FAILURE
from twisted.internet import reactor
from ftplib import FTP as FFTP
from psutil import process_iter
from signal import SIGTERM
from logging import DEBUG, basicConfig, getLogger
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from os import path

class QFTPServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking='',logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 21
		self.username = username or 'test'
		self.password = password or 'test'
		self.mocking = mocking or ''
		self.random_servers = ['ProFTPD 1.2.10','ProFTPD 1.3.4a','FileZilla ftp 0.9.43','Gene6 ftpd 3.10.0','FileZilla ftp 0.9.33','ProFTPD 1.2.8']
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

	def ftp_server_main(self):
		_q_s = self

		class CustomFTPProtocol(FTP):

			def ftp_PASS(self, password):
				if self._user == _q_s.username and password == _q_s.password:
					_q_s.logs.info(['servers',{'server':'ftp_server','action':'login','status':'success','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':_q_s.username,'password':_q_s.password}])
				else:
					_q_s.logs.info(['servers',{'server':'ftp_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':self._user,'password':password}])
				return AUTH_FAILURE

		class CustomFTPFactory(FTPFactory):
			protocol = CustomFTPProtocol
			portal = None
			
			def buildProtocol(self, address):
				p = self.protocol()
				p.portal = self.portal
				p.factory = self
				return p

		factory = CustomFTPFactory()
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False):

		if process:
			if self.close_port():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
		else:
			self.ftp_server_main()

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
			f = FFTP()
			f.connect(_ip,_port)
			f.login(_username,_password)
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
			self.logs.error(['errors',{'server':'ftp_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	from helper import server_arguments
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		ftpserver = QFTPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		ftpserver.run_server()