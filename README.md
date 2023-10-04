<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/honeypots/main/readme/honeypots.png"></p>

30 low-high level honeypots in a single PyPI package for monitoring network traffic, bots activities, and username \ password credentials. 

## Why honeypots package is very powerful?
The honeypots respond back, non-blocking, can be used as objects, or called directly with the in-built auto-configure scripts! Also, they are easy to set up and customize; it takes 1-2 seconds to spin a honeypot up. You can spin up multiple instances with the same type. For easy integration, the output can be logged to a Postgres database, file[s], terminal, or Syslog.

This honeypots package is the only package that contains all the following: dhcp, dns, elastic, ftp, http proxy, https proxy, http, https, imap, ipp, irc, ldap, memcache, mssql, mysql, ntp, oracle, pjl, pop3, postgres, rdp, redis, sip, smb, smtp, snmp, socks5, ssh, telnet, vnc.

Honeypots is in the awesome [telekom security T-Pot project!](https://github.com/telekom-security/tpotce)

## New
- Add `capture_commands` to options for capturing more information about the threat source (Look at the table if it's supported or not)

## Easy!
<img src="https://raw.githubusercontent.com/qeeqbox/honeypots/main/readme/intro.gif" style="max-width:768px"/>

## Install
```
pip3 install honeypots
```

```
# or 
sudo apt-get install postgresql
sudo apt-get install python-psycopg2
sudo apt-get install libpq-dev
pip3 install honeypots
```

## honeypots -h
```sh
Qeeqbox/honeypots customizable honeypots for monitoring network traffic, bots activities, and username\password credentials

Arguments:
  --setup               target honeypot E.g. ssh or you can have multiple E.g ssh,http,https
  --list                list all available honeypots
  --kill                kill all honeypots
  --verbose             Print error msgs

Honeypots options:
  --ip                  Override the IP
  --port                Override the Port (Do not use on multiple!)
  --username            Override the username
  --password            Override the password
  --config              Use a config file for honeypots settings
  --options             Extra options (capture_commands for capturing all threat actor data)

General options:
  --termination-strategy {input,signal} Determines the strategy to terminate by
  --test                Test a honeypot
  --auto                Setup the honeypot with random port
```

## Usage Example - Auto configuration with default ports

honeypot, or multiple honeypots separated by comma or word `all`

```
sudo -E python3 -m honeypots --setup ssh --options capture_commands
```

## Usage Example - Auto configuration with random port (No need for higher privileges)

honeypot, or multiple honeypots separated by comma or word `all`

```
python3 -m honeypots --setup ssh --auto
```

## Usage Example - Auto configure with specific ports (You might need for higher privileges)

Use as honeypot:port or multiple honeypots as honeypot:port,honeypot:port

```
sudo -E python3 -m honeypots --setup imap:143,mysql:3306,redis:6379
```

## Usage Example - Custom configure with logs location

honeypot, or multiple honeypots in a dict

```bash
sudo -E python3 -m honeypots --setup ftp --config config.json
```

#### config.json (Output to folder and terminal)
```json
{
  "logs": "file,terminal,json",
  "logs_location": "/var/log/honeypots/",
  "syslog_address": "",
  "syslog_facility": 0,
  "postgres": "",
  "sqlite_file":"",
  "db_options": [],
  "sniffer_filter": "",
  "sniffer_interface": "",
  "honeypots": {
    "ftp": {
      "port": 21,
      "ip": "0.0.0.0",
      "username": "ftp",
      "password": "anonymous",
      "log_file_name": "ftp.log",
      "max_bytes": 10000,
      "backup_count": 10,
      "options":["capture_commands"]
    }
  }
}
```

#### config.json (Output to syslog)
```json
{
  "logs": "syslog",
  "logs_location": "",
  "syslog_address": "udp://localhost:514",
  "syslog_facility": 3,
  "postgres": "",
  "sqlite_file":"",
  "db_options": [],
  "sniffer_filter": "",
  "sniffer_interface": "",
  "honeypots": {
    "ftp": {
      "port": 21,
      "ip": "0.0.0.0",
      "username": "test",
      "password": "test",
      "options":["capture_commands"]
    }
  }
}

```

#### config.json (Output to Postgres db)
```json
{
    "logs": "db_postgres",
    "logs_location": "",
    "syslog_address":"",
    "syslog_facility":0,
    "postgres":"//username:password@172.19.0.2:9999/honeypots",
    "sqlite_file":"",
    "db_options":["drop"],
    "sniffer_filter": "",
    "sniffer_interface": "",
    "honeypots": {
        "ftp": {
            "port": 21,
            "username": "test",
            "password": "test"
        }
    }
}
```

#### config.json (Output to sqlite db)
```json
{
    "logs": "db_postgres",
    "logs_location": "",
    "syslog_address":"",
    "syslog_facility":0,
    "postgres":"",
    "sqlite_file":"/home/test.db",
    "db_options":["drop"],
    "sniffer_sniffer_filter": "",
    "sniffer_interface": "",
    "honeypots": {
        "ftp": {
            "port": 21,
            "username": "test",
            "password": "test",
            "options":["capture_commands"]
        }
    }
}
```

## db structure
```json
[
  {
    "id": 1,
    "date": "2021-11-18 06:06:42.304338+00",
    "data": {
      "server": "ftp_server",
      "action": "process",
      "status": "success",
      "ip": "0.0.0.0",
      "port": "21",
      "username": "test",
      "password": "test"
    }
  }
]
```

## Usage Example - Import as object and auto test
```python
from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
qsshserver.test_server(port=9999)
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'src_ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'src_port': 38696}]
qsshserver.kill_server()
```

## Usage Example - Import as object and test with external ssh command
```python
#you need higher user permissions for binding\closing some ports

from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
```
```sh
ssh test@127.0.0.1
```
```python
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'src_ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'src_port': 38696}]
qsshserver.kill_server()
```

## All output values
```sh
'error'     :'Information about current error' 
'server'    :'Server name'
'timestamp' :'Time in ISO'
'action'    :'Query, login, etc..'
'data'      :'More info about the action'
'status'    :'The return status of the action (success or fail)'
'dest_ip'   :'Server address'
'dest_port' :'Server port'
'src_ip'    :'Attacker address'
'src_port'  :'Attacker port'
'username'  :'Attacker username'
'password'  :'Attacker password'
```

## Current Servers/Emulators
- QDNSServer
    - Server: DNS 
    - Port: 53/udp
    - Lib: Twisted.dns
    - Logs: ip, port
- QFTPServer
    - Server: FTP 
    - Port: 21/tcp
    - Lib: Twisted.ftp
    - Logs: ip, port, username and password (default)
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPProxyServer
    - Server: HTTP Proxy
    - Port: 8080/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and data
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPServer
    - Server: HTTP
    - Port: 80/tcp
    - Lib: Twisted.http
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPSServer
    - Server: HTTPS
    - Port: 443/tcp
    - Lib: Twisted.https
    - Logs: ip, port, username and password
- QIMAPServer
    - Server: IMAP
    - Port: 143/tcp
    - Lib: Twisted.imap
    - Logs: ip, port, username and password (default)
    - Options: Capture all threat actor commands and data (avalible)
- QMysqlServer
    - Emulator: Mysql
    - Port: 3306/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password
- QPOP3Server
    - Server: POP3
    - Port: 110/tcp
    - Lib: Twisted.pop3
    - Logs: ip, port, username and password (default)
    - Options: Capture all threat actor commands and data (avalible)
- QPostgresServer
    - Emulator: Postgres
    - Port: 5432/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password
- QRedisServer
    - Emulator: Redis
    - Port: 6379/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password
- QSMBServer
    - Server: Redis
    - Port: 445/tcp
    - Lib: impacket
    - Logs: ip, port and username
- QSMTPServer
    - Server: SMTP
    - Port: 25/tcp
    - Lib: smtpd
    - Logs: ip, port, username and password (default)
    - Options: Capture all threat actor commands and data (avalible)
- QSOCKS5Server
    - Server: SOCK5
    - Port: 1080/tcp
    - Lib: socketserver
    - Logs: ip, port, username and password
- QSSHServer
    - Server: SSH
    - Port: 22/tcp
    - Lib: paramiko
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QTelnetServer
    - Server: Telnet
    - Port: 23/tcp
    - Lib: Twisted
    - Logs: ip, port, username and password
- QVNCServer
    - Emulator: VNC
    - Port: 5900/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password
- QMSSQLServer
    - Emulator: MSSQL
    - Port: 1433/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password or hash
- QElasticServer
    - Emulator: Elastic
    - Port: 9200/tcp
    - Lib: http.server
    - Logs: ip, port and data
- QLDAPServer
    - Emulator: LDAP
    - Port: 389/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port, username and password
- QNTPServer
    - Emulator: NTP
    - Port: 123/udp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and data
- QMemcacheServer
    - Emulator: Memcache
    - Port: 11211/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and data
- QOracleServer
    - Emulator: Oracle
    - Port: 1521/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and connet data
- QSNMPServer
    - Emulator: SNMP
    - Port: 161/udp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and data
- QSIPServer
    - Emulator: SIP
    - Port: 5060/udp
    - Lib: Twisted.sip
    - Logs: ip, port and data
    - Options: Capture all threat actor commands and data (avalible)
- QIRCServer
    - Emulator: IRC
    - Port: 6667/tcp
    - Lib: Twisted.irc
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QPJLServer
    - Emulator: PJL
    - Port: 9100/tcp
    - Lib: Twisted
    - Logs: ip, port
    - Options: Capture all threat actor commands and data (avalible)
- QIPPServer
    - Emulator: IPP
    - Port: 631/tcp
    - Lib: Twisted
    - Logs: ip, por
    - Options: Capture all threat actor commands and data (avalible)
- QRDPServer
    - Emulator: RDP
    - Port: 3389/tcp
    - Lib: Sockets
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QDHCPServer
    - Emulator: DHCP
    - Port: 67/udp
    - Lib: Sockets
    - Logs: ip, port

## Open Shell
[![Open in Cloud Shell](https://img.shields.io/static/v1?label=%3E_&message=Open%20in%20Cloud%20Shell&color=3267d6&style=flat-square)](https://ssh.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/qeeqbox/honeypots&tutorial=README.md) [![Open in repl.it Shell](https://img.shields.io/static/v1?label=%3E_&message=Open%20in%20repl.it%20Shell&color=606c74&style=flat-square)](https://repl.it/github/qeeqbox/honeypots)

## acknowledgment
- By using this framework, you are accepting the license terms of all these packages: `pipenv twisted psutil psycopg2-binary dnspython requests impacket paramiko redis mysql-connector pycryptodome vncdotool service_identity requests[socks] pygments http.server`
- Let me know if I missed a reference or resource!

## Notes
- Almost all servers and emulators are stripped-down - You can adjust that as needed

## Other Projects
[![](https://github.com/qeeqbox/.github/blob/main/data/social-analyzer.png)](https://github.com/qeeqbox/social-analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/analyzer.png)](https://github.com/qeeqbox/analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/chameleon.png)](https://github.com/qeeqbox/chameleon) [![](https://github.com/qeeqbox/.github/blob/main/data/osint.png)](https://github.com/qeeqbox/osint) [![](https://github.com/qeeqbox/.github/blob/main/data/url-sandbox.png)](https://github.com/qeeqbox/url-sandbox) [![](https://github.com/qeeqbox/.github/blob/main/data/mitre-visualizer.png)](https://github.com/qeeqbox/mitre-visualizer) [![](https://github.com/qeeqbox/.github/blob/main/data/woodpecker.png)](https://github.com/qeeqbox/woodpecker) [![](https://github.com/qeeqbox/.github/blob/main/data/docker-images.png)](https://github.com/qeeqbox/docker-images) [![](https://github.com/qeeqbox/.github/blob/main/data/seahorse.png)](https://github.com/qeeqbox/seahorse) [![](https://github.com/qeeqbox/.github/blob/main/data/rhino.png)](https://github.com/qeeqbox/rhino) [![](https://github.com/qeeqbox/.github/blob/main/data/raven.png)](https://github.com/qeeqbox/raven) [![](https://github.com/qeeqbox/.github/blob/main/data/image-analyzer.png)](https://github.com/qeeqbox/image-analyzer)

