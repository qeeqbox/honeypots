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
filterwarnings(action='ignore',module='.*paramiko.*')

from paramiko import ServerInterface,Transport,RSAKey,AutoAddPolicy
from socket import socket,AF_INET,SOCK_STREAM,SOL_SOCKET,SO_REUSEADDR
from _thread import start_new_thread
from io import StringIO
from random import choice
from multiprocessing import Process
from psutil import process_iter
from signal import SIGTERM
from time import sleep
from paramiko import SSHClient
from logging import DEBUG, basicConfig, getLogger
from tempfile import gettempdir,_get_candidate_names
from subprocess import Popen
from socket import socket as ssocket
from socket import AF_INET,SOCK_STREAM
from email.parser import BytesParser
from pathlib import Path
from os import path
from honeypots.helper import server_arguments, get_free_port, CustomHandler
from uuid import uuid4

class QSSHServer():
	def __init__(self,ip=None,port=None,username=None,password=None,mocking=False,logs=None):
		self.ip= ip or '0.0.0.0'
		self.port = port or 22
		self.username = username or "test"
		self.password = password or "test"
		self.mocking = mocking or ''
		self.random_servers = ['OpenSSH 7.5','OpenSSH 7.3','Serv-U SSH Server 15.1.1.108','OpenSSH 6.4']
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

	def generate_pub_pri_keys(self):
		try:
			key = RSAKey.generate(2048)
			string_io = StringIO()
			key.write_private_key(string_io)
			return key.get_base64(), string_io.getvalue()
		except:
			pass
		return None,None

	def ssh_server_main(self):
		_q_s = self

		class SSHHandle(ServerInterface):

			def __init__(self,ip,port):
				self.ip = ip
				self.port = port
				ServerInterface.__init__(self)

			def check_auth_password(self, username, password):
				username, password = username.encode("utf-8"), password.encode("utf-8")
				if username ==  _q_s.username and password == _q_s.password:
					_q_s.logs.info(["servers",{'server':'ssh_server','action':'login','status':'success','ip':self.ip,'port':self.port,'username':username,'password':password}])
				else:
					_q_s.logs.info(["servers",{'server':'ssh_server','action':'login','status':'failed','ip':self.ip,'port':self.port,'username':username,'password':password}])

		def ConnectionHandle(client,priv):
			try:
				t = Transport(client)
				ip, port = client.getpeername()
				_q_s.logs.info(["servers",{'server':'ssh_server','action':'connection','ip':ip,'port':port}])
				t.local_version = 'SSH-2.0-'+choice(self.random_servers)
				t.add_server_key(RSAKey(file_obj=StringIO(priv)))
				t.start_server(server=SSHHandle(ip,port))
				chan = t.accept(1)
				if not chan is None:
					chan.close()
			except:
				pass

		sock = socket(AF_INET,SOCK_STREAM)
		sock.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)
		sock.bind((self.ip, self.port))
		sock.listen(1)
		pub, priv = self.generate_pub_pri_keys()
		while True:
			try:
				client, addr = sock.accept()
				start_new_thread(ConnectionHandle,(client,priv,))
			except:
				pass

	def run_server(self,process=False,auto=False):
		if process:
			if auto:
				port = get_free_port()
				if port > 0:
					self.port = port
					self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
					if self.process.poll() is None:
						self.logs.info(["servers",{'server':'ssh_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
					else:
						self.logs.info(["servers",{'server':'ssh_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'ssh_server','action':'setup','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
			elif self.close_port() and self.kill_server():
				self.process = Popen(['python3',path.realpath(__file__),'--custom','--ip',str(self.ip),'--port',str(self.port),'--username',str(self.username),'--password',str(self.password),'--mocking',str(self.mocking),'--logs',str(self._logs)])
				if self.process.poll() is None:
					self.logs.info(["servers",{'server':'ssh_server','action':'process','status':'success','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
				else:
					self.logs.info(["servers",{'server':'ssh_server','action':'process','status':'error','ip':self.ip,'port':self.port,'username':self.username,'password':self.password}])
		else:
			self.ssh_server_main()

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
			ssh = SSHClient()
			ssh.set_missing_host_key_policy(AutoAddPolicy()) #if you have default ones, remove them before using this.. 
			ssh.connect(_ip, port=_port,username=_username,password=_password)
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
			self.logs.error(['errors',{'server':'ssh_server','error':'port_open','type':'Port {} still open..'.format(self.ip)}])
			return False

if __name__ == '__main__':
	parsed = server_arguments()
	if parsed.docker or parsed.aws or parsed.custom:
		qsshserver = QSSHServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
		qsshserver.run_server()