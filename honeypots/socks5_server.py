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

from multiprocessing import Process
from psutil import process_iter
from signal import SIGTERM
from time import sleep
from logging import DEBUG, basicConfig, getLogger
from socketserver import TCPServer, StreamRequestHandler, ThreadingMixIn
from struct import unpack
from requests import get
from pathlib import Path
from os import path
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from subprocess import Popen
from tempfile import gettempdir,_get_candidate_names
from honeypots.helper import server_arguments, get_free_port, CustomHandler
from uuid import uuid4

class QSOCKS5Server():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 1080
		self.username = username or "test"
		self.password = password or "test"
		self.mocking = mocking or ''
		self.process = None
		self._logs = logs
		self.setup_logger(self._logs)
		self.disable_logger()

	def setup_logger(self,logs):
		self.logs = getLogger('honeypotslogger'+'_'+__class__.__name__+'_'+str(uuid4())[:8])
		self.logs.setLevel(DEBUG)
		self.logs.addHandler(CustomHandler())

	def disable_logger(self):
		temp_name = path.join(gettempdir(), next(_get_candidate_names()))

	def socks5_server_main(self):
		_q_s = self

		class CustomStreamRequestHandler(StreamRequestHandler):
			def handle(self):
				_q_s.logs.info(["servers",{'server':'socks5_server','action':'connection','ip':self.client_address[0],'port':self.client_address[1]}])
				v,m = unpack("!BB", self.connection.recv(2))
				if v == 5:
					if 2 in unpack("!"+"B"*m,self.connection.recv(m)):
						self.connection.sendall(b'\x05\x02')
						if 1 in unpack("B",self.connection.recv(1)):
							_len = ord(self.connection.recv(1))
							username = self.connection.recv(_len)
							_len = ord(self.connection.recv(1))
							password = self.connection.recv(_len)
							if username == _q_s.username and password == _q_s.password:
								_q_s.logs.info(["servers",{'server':'socks5_server','action':'login','status':'success','ip':self.client_address[0],'port':self.client_address[1],'username':_q_s.username,'password':_q_s.password}])
							else:
								_q_s.logs.info(["servers",{'server':'socks5_server','action':'login','status':'failed','ip':self.client_address[0],'port':self.client_address[1],'username':username,'password':password}])
				self.server.close_request(self.request)

		class ThreadingTCPServer(ThreadingMixIn, TCPServer):
			pass

		TCPServer.allow_reuse_address = True
		server = ThreadingTCPServer((self.ip, self.port), CustomStreamRequestHandler)
		server.serve_forever()

	def run_server(self,process=False,auto=False):
		if process:
			if self.close_port() and self.kill_server():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
		else:
			self.socks5_server_main()

	def run_server(self,process=False,auto=False):
		if process:
			if auto:
				port = get_free_port()
				if port > 0:
					self.port = port
					self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
					if self.process.poll() is None:
						self.logs.info(["servers",{'server':'socks5_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
					else:
						self.logs.info(["servers",{'server':'socks5_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'socks5_server','action':'setup','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
			elif self.close_port() and self.kill_server():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
				if self.process.poll() is None:
					self.logs.info(["servers",{'server':'socks5_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'socks5_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
		else:
			self.socks5_server_main()

	def kill_server(self,process=False):
		try:
			for process in process_iter():
				cmdline = ' '.join(process.cmdline())
				if '--custom' in cmdline and Path(__file__).name in cmdline:
					process.send_signal(SIGTERM)
					process.kill()
			if self.process != None:
				self.process.kill()
			return True
		except:
			pass
		return False

	def test_server(self,ip=None,port=None,username=None,password=None):
		try:
			sleep(2)
			_ip = ip or self.ip
			_port = port or self.port 
			_username = username or self.username
			_password = password or self.password
			get('https://yahoo.com', proxies=dict(http='socks5://{}:{}@{}:{}'.format(_username,_password,_ip,_port),https='socks5://{}:{}@{}:{}'.format(_username,_password,_ip,_port)))
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
			self.logs.error(['errors',{'server':'socks5_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		QSOCKS5Server = QSOCKS5Server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		QSOCKS5Server.run_server()