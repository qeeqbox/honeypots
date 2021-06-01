"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
"""

from warnings import filterwarnings
filterwarnings(action='ignore', category=DeprecationWarning)

from smtpd import SMTPChannel, SMTPServer
from asyncore import loop
from base64 import b64decode
from time import sleep
from smtplib import SMTP
from os import path
from subprocess import Popen
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, set_local_vars
from uuid import uuid4


class QSMTPServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 25
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.random_servers = []
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)

    def smtp_server_main(self):
        _q_s = self

        class CustomSMTPChannel(SMTPChannel):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def smtp_EHLO(self, arg):
                _q_s.logs.info(["servers", {'server': 'smtp_server', 'action': 'connection', 'ip': self.addr[0], 'port':self.addr[1]}])
                if not arg:
                    self.push('501 Syntax: HELO hostname')
                if self._SMTPChannel__greeting:
                    self.push('503 Duplicate HELO/EHLO')
                else:
                    self._SMTPChannel__greeting = arg
                    self.push('250-{0} Hello {1}'.format(self._SMTPChannel__fqdn, arg))
                    self.push('250-8BITMIME')
                    self.push('250-AUTH LOGIN PLAIN')
                    self.push('250 STARTTLS')

            def smtp_AUTH(self, arg):
                try:
                    if arg.startswith('PLAIN '):
                        _, username, password = b64decode(arg.split(' ')[1].strip()).decode("utf-8").split('\0')
                        username = self.check_bytes(username)
                        password = self.check_bytes(password)
                        if username == _q_s.username and password == _q_s.password:
                            _q_s.logs.info(["servers", {'server': 'smtp_server', 'action': 'login', 'status': 'success', 'ip': self.addr[0], 'port':self.addr[1], 'username':_q_s.username, 'password':_q_s.password}])
                        else:
                            _q_s.logs.info(["servers", {'server': 'smtp_server', 'action': 'login', 'status': 'faild', 'ip': self.addr[0], 'port':self.addr[1], 'username':username, 'password':password}])
                except Exception as e:
                    print(e)
                    _q_s.logs.error(["errors", {'server': 'smtp_server', 'error': 'smtp_AUTH', "type": "error -> " + repr(e)}])

                self.push('235 Authentication successful')

            def __getattr__(self, name):
                self.smtp_QUIT(0)

        class CustomSMTPServer(SMTPServer):
            def __init__(self, localaddr, remoteaddr):
                SMTPServer.__init__(self, localaddr, remoteaddr)

            def process_message(self, peer, mailfrom, rcpttos, data, mail_options=None, rcpt_options=None):
                return

            def handle_accept(self):
                conn, addr = self.accept()
                CustomSMTPChannel(self, conn, addr)

        CustomSMTPServer((self.ip, self.port), None)
        loop(timeout=1.1, use_poll=True)

    def run_server(self, process=False, auto=False):
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'smtp_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'smtp_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smtp_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'smtp_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smtp_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.smtp_server_main()

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            sleep(2)
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            s = SMTP(_ip, _port)
            s.ehlo()
            s.login(_username, _password)
            s.sendmail("fromtest", "totest", "Nothing")
            s.quit()
        except BaseException:
            pass

    def close_port(self):
        ret = close_port_wrapper('smtp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('smtp_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmtpserver = QSMTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        qsmtpserver.run_server()
