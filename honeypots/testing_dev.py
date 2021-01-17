from dns_server import QDNSServer
from ftp_server import QFTPServer
from http_proxy_server import QHTTPPoxyServer
from http_server import QHTTPServer
from https_server import QHTTPSServer
from imap_server import QIMAPServer
from mysql_server import QMysqlServer
from pop3_server import QPOP3Server
from postgres_server import QPostgresServer
from redis_server import QRedisServer
from smb_server import QSMBServer
from smtp_server import QSMTPServer
from socks5_server import QSOCKS5Server
from ssh_server import QSSHServer
from telnet_server import QTelnetServer
from vnc_server import QVNCServer
from helper import server_arguments,clean_all
from time import sleep

parsed = server_arguments()
parsed.ip = "0.0.0.0"
parsed.logs = "terminal"
parsed.mocking = True
parsed.port = 9999

print("Testing QDNSServer")
qdnsserver = QDNSServer(ip=parsed.ip,port=parsed.port,resolver_addresses=parsed.resolver_addresses,logs=parsed.logs)
qdnsserver.run_server(process=True)
sleep(1)
qdnsserver.test_server(ip=parsed.ip,port=parsed.port,domain=parsed.domain)
qdnsserver.kill_server()
clean_all()

print("Testing QFTPServer")
qftpserver = QFTPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qftpserver.run_server(process=True)
sleep(1)
qftpserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qftpserver.kill_server()
clean_all()

print("Testing QHTTPPoxyServer")
qhttpproxyserver = QHTTPPoxyServer(ip=parsed.ip,port=parsed.port,mocking=parsed.mocking,logs=parsed.logs)
qhttpproxyserver.run_server(process=True)
sleep(1)
qhttpproxyserver.test_server(ip=parsed.ip,port=parsed.port,domain=parsed.domain)
qhttpproxyserver.kill_server()
clean_all()

print("Testing QHTTPServer")
qhttpserver = QHTTPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qhttpserver.run_server(process=True)
sleep(1)
qhttpserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qhttpserver.kill_server()
clean_all()

print("Testing QHTTPSServer")
qhttpsserver = QHTTPSServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qhttpsserver.run_server(process=True)
sleep(1)
qhttpsserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qhttpsserver.kill_server()
clean_all()

print("Testing QIMAPServer")
qimapserver = QIMAPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qimapserver.run_server(process=True)
sleep(1)
qimapserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qimapserver.kill_server()
clean_all()

print("Testing QMysqlServer")
qmysqlserver = QMysqlServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qmysqlserver.run_server(process=True)
sleep(1)
qmysqlserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qmysqlserver.kill_server()
clean_all()

print("Testing QTPOP3Server")
qpop3server = QPOP3Server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qpop3server.run_server(process=True)
sleep(1)
qpop3server.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qpop3server.kill_server()
clean_all()

print("Testing QPostgresServer")
qpostgresserver = QPostgresServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qpostgresserver.run_server(process=True)
sleep(1)
qpostgresserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qpostgresserver.kill_server()
clean_all()

print("Testing QRedisServer")
qredisserver = QRedisServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qredisserver.run_server(process=True)
sleep(1)
qredisserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qredisserver.kill_server()
clean_all()

print("Testing QSMBServer")
qsmbserver = QSMBServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qsmbserver.run_server(process=True)
sleep(1)
qsmbserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qsmbserver.kill_server()
clean_all()

print("Testing QSMTPServer")
qsmtpserver = QSMTPServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qsmtpserver.run_server(process=True)
sleep(1)
qsmtpserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qsmtpserver.kill_server()
clean_all()

print("Testing QSOCKS5Server")
qsocks5server = QSOCKS5Server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qsocks5server.run_server(process=True)
sleep(1)
qsocks5server.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qsocks5server.kill_server()
clean_all()

print("Testing QSSHServer")
qsshserver = QSSHServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qsshserver.run_server(process=True)
sleep(1)
qsshserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qsshserver.kill_server()
clean_all()

print("Testing QTelnetServer")
qtelnetserver = QTelnetServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qtelnetserver.run_server(process=True)
sleep(1)
qtelnetserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qtelnetserver.kill_server()
clean_all()

print("Testing QVNCServer")
qvncserver = QVNCServer(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password,mocking=parsed.mocking,logs=parsed.logs)
qvncserver.run_server(process=True)
sleep(1)
qvncserver.test_server(ip=parsed.ip,port=parsed.port,username=parsed.username,password=parsed.password)
qvncserver.kill_server()
clean_all()
