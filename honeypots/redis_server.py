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

from twisted.internet.protocol import Protocol,Factory
from twisted.internet import reactor
from psutil import process_iter
from signal import SIGTERM
from logging import DEBUG, basicConfig, getLogger
from redis import StrictRedis
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from os import path

class QRedisServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 6379
		self.username = username or "test"
		self.password = password or "test"
		self.mocking = mocking or ''
		self.process = None
		self._logs = logs
		self.setup_logger(self._logs)
		#self.disable_logger()

	def disable_logger(self):
		temp_name = path.join(gettempdir(), next(_get_candidate_names()))
		tlog.startLogging(open(temp_name, 'w'), setStdout=False)

	def setup_logger(self,logs):
		self.logs = getLogger('honeypotslogger')
		self.logs.setLevel(DEBUG)
		if logs:
			
			basicConfig()
		else:
			basicConfig()

	def redis_server_main(self):
		_q_s = self

		class CustomRedisProtocol(Protocol):

			def get_command(self,data):
				try:
					_data = data.decode('utf-8').split('\x0d\x0a')
					if _data[0][0] == "*":
						_count = int(_data[0][1]) - 1
						_data.pop(0)
						if _data[0::2][0][0] == "$" and len(_data[1::2][0]) == int(_data[0::2][0][1]):
							return _count,_data[1::2][0]
				except Exception as e:
					print(e)

				return 0,""

			def parse_data(self,c,data):
				_data = data.decode('utf-8').split('\r\n')[3::]
				user, password = "",""
				if c == 2:
					_ = 0
					if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
						user =(_data[1::2][_])
					_ = 1
					if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
						password  = (_data[1::2][_])
				if c == 1:
					_ = 0
					if _data[0::2][_][0] == "$" and len(_data[1::2][_]) == int(_data[0::2][_][1]):
						password =(_data[1::2][_])
				if c == 2 or c == 1:
					if user == _q_s.username and password == _q_s.password:
						_q_s.logs.info(["servers",{'server':'redis_server','action':'login','status':'success','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':_q_s.username,'password':_q_s.password}])
					else:
						_q_s.logs.info(["servers",{'server':'redis_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':user,'password':password}])

			def connectionMade(self):
				self._state = 1
				self._variables = {}
				_q_s.logs.info(["servers",{'server':'redis_server','action':'connection','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port}])

			def dataReceived(self, data):
				c,command = self.get_command(data)
				if command == "AUTH":
					self.parse_data(c,data)
					self.transport.write(b"-ERR invalid password\r\n")
				else:
					self.transport.write(b"-ERR unknown command '{}'\r\n".format(command))
				self.transport.loseConnection()

		factory = Factory()
		factory.protocol = CustomRedisProtocol
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False):

		if process:
			if self.close_port():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
		else:
			self.redis_server_main()

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
			r= StrictRedis.from_url('redis://{}:{}@{}:{}/1'.format(_username,_password,_ip,_port))
			for key in r.scan_iter("user:*"):
				pass
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
			self.logs.error(['errors',{'server':'redis_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	from helper import server_arguments
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qredisserver = QRedisServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		qredisserver.run_server()