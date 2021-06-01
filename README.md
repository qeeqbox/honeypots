<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/honeypots/main/readme/honeypots.png"></p>

18 different honeypots in a single PyPI package for monitoring network traffic, bots activities, and username \ password credentials. All honeypots are non-blocking and can be used as objects or called directly with the in-built auto-configure scripts.

The current available honeypots are: dns ftp httpproxy http https imap mysql pop3 postgres redis smb smtp socks5 ssh telnet vnc mssql elastic.

## Install
```
pip3 install honeypots
```

## Usage Example - Auto configure

honeypot, or multiple honeypots separated by comma or word `all`

```
python3 -m honeypots --setup ssh
```

## Usage Example - Auto configure with logs location

honeypot, or multiple honeypots separated by comma or word `all`

```
python3 -m honeypots --setup ssh --config config.json

#config.json
{
    "logs":"file,terminal",
    "logs_location":"/temp/honeypots_logs/"
} 
```

## Usage Example - Custom configure

honeypot, or multiple honeypots in a dict

```
python3 -m honeypots --setup ftp --config config.json

#config.json
{
    "logs":"file,terminal",
    "logs_location":"/temp/honeypots_logs/"
    "honeypots": {
        "ftp": {
            "port": 21,
            "ip": "0.0.0.0",
            "username": "test",
            "password": "test"
            }
        }
}
```

## Usage Example - Auto configure with specific ports

Use as honeypot:port or multiple honeypots as honeypot:port,honeypot:port

```
python3 -m honeypots --setup imap:143,mysql:3306,redis:6379
```

## Usage Example - Import as object and auto test

```
#you need higher user permissions for binding\closing some ports

ip= String E.g. 0.0.0.0
port= Int E.g. 9999
username= String E.g. Test
password= String E.g. Test
mocking= Boolean or String E.g OpenSSH 7.0
logs= String E.g db, terminal or all
always remember to add process=true to run_server() for non-blocking
```

```
from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
qsshserver.test_server(port=9999)
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'port': 38696}]
qsshserver.kill_server()
```

## Usage Example - Import as object and test with external ssh command
```
#you need higher user permissions for binding\closing some ports

from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
```
```
ssh test@127.0.0.1
```
```
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'port': 38696}]
qsshserver.kill_server()
```

## Current Servers/Emulators
- QDNSServer <- DNS (Server using Twisted)
- QFTPServer <- FTP (Server using Twisted)
- QHTTPProxyServer <- HTTP Proxy (Server using Twisted)
- QHTTPServer <- HTTP (Server using Twisted)
- QHTTPSServer <- HTTPS (Server using Twisted)
- QIMAPServer <- IMAP (Server using Twisted)
- QMysqlServer <- Mysql (Emulator using Twisted)
- QPOP3Server <- POP3 (Server using Twisted)
- QPostgresServer <- Postgres (Emulator using Twisted)
- QRedisServer <- Redis (Emulator using Twisted)
- QSMBServer <- SMB (Server using impacket)
- QSMTPServer <- STMP (Server using smtpd)
- QSOCKS5Server <- SOCK5 (Server using socketserver)
- QSSHServer <- SSH (Server using socket)
- QTelnetServer <- TELNET (Server using Twisted)
- QVNCServer <- VNC (Emulator using Twisted)
- QMSSQLServer <- MSSQL (Emulator using Twisted)
- QElasticServer <- Elastic (Emulator using http.server)

## acknowledgement
- By using this framework, you are accepting the license terms of all these packages: `pipenv twisted psutil psycopg2-binary dnspython requests impacket paramiko redis mysql-connector pycryptodome vncdotool service_identity requests[socks] pygments http.server`
- Let me know if I missed a reference or resource!

## Some Articles
[securityonline](https://securityonline.info/honeypots-16-honeypots-in-a-single-pypi-package/)

## Notes
- Almost all servers and emulators are stripped-down - You can adjust that as needed

## Other Projects
[![](https://github.com/qeeqbox/.github/blob/main/data/social-analyzer.png)](https://github.com/qeeqbox/social-analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/analyzer.png)](https://github.com/qeeqbox/analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/chameleon.png)](https://github.com/qeeqbox/chameleon) [![](https://github.com/qeeqbox/.github/blob/main/data/osint.png)](https://github.com/qeeqbox/osint) [![](https://github.com/qeeqbox/.github/blob/main/data/url-sandbox.png)](https://github.com/qeeqbox/url-sandbox) [![](https://github.com/qeeqbox/.github/blob/main/data/mitre-visualizer.png)](https://github.com/qeeqbox/mitre-visualizer) [![](https://github.com/qeeqbox/.github/blob/main/data/woodpecker.png)](https://github.com/qeeqbox/woodpecker) [![](https://github.com/qeeqbox/.github/blob/main/data/docker-images.png)](https://github.com/qeeqbox/docker-images) [![](https://github.com/qeeqbox/.github/blob/main/data/seahorse.png)](https://github.com/qeeqbox/seahorse) [![](https://github.com/qeeqbox/.github/blob/main/data/rhino.png)](https://github.com/qeeqbox/rhino)
