.. image:: https://raw.githubusercontent.com/qeeqbox/honeypots/main/readme/honeypots.png

Easy to setup customizable honeypots for monitoring network traffic, bots activities and username\password credentials.

The current available honeypots are: dns ftp httpproxy http https imap mysql pop3 postgres redis smb smtp socks5 ssh telnet vnc

Install
==========

.. code:: bash

    pip3 install honeypots

Usage Example - Auto configure
==============================
Use a honeypot, or multiple honeypots separated by comma or word all

.. code:: bash

    python3 -m honeypots ssh

Usage Example - Auto configure with specific ports
==================================================
Use as honeypot:port or multiple honeypots as honeypot:port,honeypot:port

.. code:: bash

    python3 -m honeypots imap:143,mysql:3306,redis:6379

Usage Example - Import as object and auto test
==============================================

.. code:: python

    #ip= String E.g. 0.0.0.0
    #port= Int E.g. 9999
    #username= String E.g. Test
    #password= String E.g. Test
    #mocking= Boolean or String E.g OpenSSH 7.0
    #logs= String E.g db, terminal or all
    #always remember to add process=true to run_server() for non-blocking

    from honeypots import QSSHServer
    qsshserver = QSSHServer(port=9999)
    qsshserver.run_server(process=True)
    qsshserver.test_server(port=9999)
    INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'port': 38696}]
    qsshserver.kill_server()

Usage Example - Import as object and test with external ssh command
===================================================================

.. code:: python

    from honeypots import QSSHServer
    qsshserver = QSSHServer(port=9999)
    qsshserver.run_server(process=True)

.. code:: bash

    ssh test@127.0.0.1

Honeypot answer

.. code:: python

    INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'port': 38696}]

Close the honeypot

.. code:: python

    qsshserver.kill_server()

Current Servers/Emulators
=========================
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

acknowledgement
===============
By using this framework, you are accepting the license terms of all these packages: `pipenv twisted psutil psycopg2-binary dnspython requests impacket paramiko redis mysql-connector pycryptodome vncdotool service_identity requests[socks] pygments`