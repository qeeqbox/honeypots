from .dns_server import QDNSServer
from .ftp_server import QFTPServer
from .http_proxy_server import QHTTPProxyServer
from .http_server import QHTTPServer
from .https_server import QHTTPSServer
from .imap_server import QIMAPServer
from .mysql_server import QMysqlServer
from .pop3_server import QPOP3Server
from .postgres_server import QPostgresServer
from .redis_server import QRedisServer
from .smb_server import QSMBServer
from .smtp_server import QSMTPServer
from .socks5_server import QSOCKS5Server
from .ssh_server import QSSHServer
from .telnet_server import QTelnetServer
from .vnc_server import QVNCServer
from .helper import server_arguments, clean_all
from .time import sleep

print("Testing QDNSServer")
qdnsserver = QDNSServer()
qdnsserver.run_server(process=True, auto=True)
sleep(1)
qdnsserver.test_server()
qdnsserver.kill_server()
clean_all()

print("Testing QFTPServer")
qftpserver = QFTPServer()
qftpserver.run_server(process=True, auto=True)
sleep(1)
qftpserver.test_server()
qftpserver.kill_server()
clean_all()

print("Testing QHTTPProxyServer")
qhttpproxyserver = QHTTPProxyServer()
qhttpproxyserver.run_server(process=True, auto=True)
sleep(1)
qhttpproxyserver.test_server()
qhttpproxyserver.kill_server()
clean_all()

print("Testing QHTTPServer")
qhttpserver = QHTTPServer()
qhttpserver.run_server(process=True, auto=True)
sleep(1)
qhttpserver.test_server()
qhttpserver.kill_server()
clean_all()

print("Testing QHTTPSServer")
qhttpsserver = QHTTPSServer()
qhttpsserver.run_server(process=True, auto=True)
sleep(1)
qhttpsserver.test_server()
qhttpsserver.kill_server()
clean_all()

print("Testing QIMAPServer")
qimapserver = QIMAPServer()
qimapserver.run_server(process=True, auto=True)
sleep(1)
qimapserver.test_server()
qimapserver.kill_server()
clean_all()

print("Testing QMysqlServer")
qmysqlserver = QMysqlServer()
qmysqlserver.run_server(process=True, auto=True)
sleep(1)
qmysqlserver.test_server()
qmysqlserver.kill_server()
clean_all()

print("Testing QTPOP3Server")
qpop3server = QPOP3Server()
qpop3server.run_server(process=True, auto=True)
sleep(1)
qpop3server.test_server()
qpop3server.kill_server()
clean_all()

print("Testing QPostgresServer")
qpostgresserver = QPostgresServer()
qpostgresserver.run_server(process=True, auto=True)
sleep(1)
qpostgresserver.test_server()
qpostgresserver.kill_server()
clean_all()

print("Testing QRedisServer")
qredisserver = QRedisServer()
qredisserver.run_server(process=True, auto=True)
sleep(1)
qredisserver.test_server()
qredisserver.kill_server()
clean_all()

print("Testing QSMBServer")
qsmbserver = QSMBServer()
qsmbserver.run_server(process=True, auto=True)
sleep(1)
qsmbserver.test_server()
qsmbserver.kill_server()
clean_all()

print("Testing QSMTPServer")
qsmtpserver = QSMTPServer()
qsmtpserver.run_server(process=True, auto=True)
sleep(1)
qsmtpserver.test_server()
qsmtpserver.kill_server()
clean_all()

print("Testing QSOCKS5Server")
qsocks5server = QSOCKS5Server()
qsocks5server.run_server(process=True, auto=True)
sleep(1)
qsocks5server.test_server()
qsocks5server.kill_server()
clean_all()

print("Testing QSSHServer")
qsshserver = QSSHServer()
qsshserver.run_server(process=True, auto=True)
sleep(1)
qsshserver.test_server()
qsshserver.kill_server()
clean_all()

print("Testing QTelnetServer")
qtelnetserver = QTelnetServer()
qtelnetserver.run_server(process=True, auto=True)
sleep(1)
qtelnetserver.test_server()
qtelnetserver.kill_server()
clean_all()

print("Testing QVNCServer")
qvncserver = QVNCServer()
qvncserver.run_server(process=True, auto=True)
sleep(1)
qvncserver.test_server()
qvncserver.kill_server()
clean_all()
