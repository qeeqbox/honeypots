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
from twisted.python import log as tlog
from tempfile import gettempdir,_get_candidate_names
from struct import pack
from hashlib import sha1
from mysql.connector import connect as mysqlconnect
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from pathlib import Path
from pathlib import Path
from os import path

class QMysqlServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,dict_=None,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 3306
		self.username = username or "test"
		self.password = password or "test"
		self.mocking = mocking or ''
		self.file_name = dict_ or None
		if not dict_:
			self.words = ["test"]
		else:
			self.load_words()
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

	def load_words(self,):
		with open(self.file_name, 'r') as file:
			self.words = file.read().splitlines()

	def greeting(self):
		base = ['\x0a','5.7.00' + '\0','\x36\x00\x00\x00','12345678' + '\0','\xff\xf7','\x21','\x02\x00','\x0f\x81','\x15','\0' * 10,'123456789012' + '\0','mysql_native_password' + '\0']
		payload_len = list(pack('<I',len(''.join(base))))
		#payload_len[3] = '\x00'
		string_ = chr(payload_len[0]) + chr(payload_len[1]) + chr(payload_len[2]) + '\x00' + ''.join(base)
		return string_

	def too_many(self):
		base = ['\xff','\x10\x04','#08004','Too many connections']
		payload_len = list(pack('<I',len(''.join(base))))
		#payload_len[3] = '\x02'
		string_ = chr(payload_len[0]) + chr(payload_len[1]) + chr(payload_len[2]) + '\x02' + ''.join(base)
		return string_

	def parse_data(self,data):
		username,password = '',''
		try:
			username_len = data[36:].find(b'\x00')
			username = data[36:].split(b'\x00')[0]
			password_len = ord(data[36+username_len+1])
			password = data[36+username_len+2:36+username_len+2+password_len]
			rest_ = data[36+username_len+2+password_len:]
			if b'mysql_native_password' in rest_:
				if len(password) == 20:
					return username,password,True
		except:
			pass
		return username,password,False

	def decode(self,hash):
		try:
			for word in self.words:
				temp = word
				word = word.strip('\n')
				hash1 = sha1(word).digest()
				hash2 = sha1(hash1).digest()
				encrypted = ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(hash1,sha1('12345678123456789012' + hash2).digest()))
				if encrypted == hash:
					return temp
		except:
			pass

		return None

	def mysql_server_main(self):
		_q_s = self

		class CustomMysqlProtocol(Protocol):

			_state = None

			def connectionMade(self):
				self._state = 1
				self.transport.write(_q_s.greeting().encode())
				_q_s.logs.info(["servers",{'server':'mysql_server','action':'connection','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port}])

			def dataReceived(self, data):
				if self._state == 111111111111:
					username, password, good = _q_s.parse_data(data)
					if good:
						if password:
							_x = _q_s.decode(password)
							if _x == _q_s.password and _x != None:
								_q_s.logs.info(["servers",{'server':'mysql_server','action':'login','status':'success','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':_q_s.username,'password':_q_s.password}])
							else:
								_q_s.logs.info(["servers",{'server':'mysql_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':username,'password':password}])
						else:
							_q_s.logs.info(["servers",{'server':'mysql_server','action':'login','status':'failed','ip':self.transport.getPeer().host,'port':self.transport.getPeer().port,'username':'UnKnown','password':''.join(hex(ord(c))[2:] for c in data)}])

					self.transport.write(_q_s.too_many().encode())
				else:
					self.transport.loseConnection()

			def connectionLost(self, reason):
				self._state = None

		factory = Factory()
		factory.protocol = CustomMysqlProtocol
		reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
		reactor.run()

	def run_server(self,process=False):
		if process:
			if self.close_port():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
		else:
			self.mysql_server_main()

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
			cnx = mysqlconnect(user=_username, password=_password, host=_ip, port=_port,database='test',connect_timeout=1000)
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
			self.logs.error(['errors',{'server':'mysql_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	from helper import server_arguments
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qmysqlserver = QMysqlServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		qmysqlserver.run_server()
