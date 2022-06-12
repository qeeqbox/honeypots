'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

from warnings import filterwarnings
filterwarnings(action='ignore', category=DeprecationWarning)

from smtpd import SMTPChannel, SMTPServer
from asyncore import loop
from base64 import b64decode
from os import path, getenv
from subprocess import Popen
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4
from contextlib import suppress


class QSMTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 25
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''

    def smtp_server_main(self):
        _q_s = self

        class CustomSMTPChannel(SMTPChannel):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def found_terminator(self):
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        line = self._emptystring.join(self.received_lines).decode()
                        command = None
                        arg = None
                        data = None
                        if line.find(' ') < 0:
                            command = line.upper()
                        else:
                            command = line.split(' ')[0].upper()
                            arg = line.split(' ')[1].strip()
                            if len(line.split(' ')) > 2:
                                data = line.split(' ', 2)[2]
                        if command != "HELO" and command != "EHLO":
                            _q_s.logs.info({'server': 'smtp_server', 'action': 'connection', 'src_ip': self.addr[0], 'src_port': self.addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "data": {"command": command, "arg": arg, "data": data}})
                super().found_terminator()

            def smtp_EHLO(self, arg):
                _q_s.logs.info({'server': 'smtp_server', 'action': 'connection', 'src_ip': self.addr[0], 'src_port': self.addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
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
                with suppress(Exception):
                    if arg.startswith('PLAIN '):
                        _, username, password = b64decode(arg.split(' ')[1].strip()).decode('utf-8').split('\0')
                        username = self.check_bytes(username)
                        password = self.check_bytes(password)
                        status = 'failed'
                        if username == _q_s.username and password == _q_s.password:
                            username = _q_s.username
                            password = _q_s.password
                            status = 'success'
                        _q_s.logs.info({'server': 'smtp_server', 'action': 'login', 'status': status, 'src_ip': self.addr[0], 'src_port': self.addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})

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
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'smtp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.smtp_server_main()

    def close_port(self):
        ret = close_port_wrapper('smtp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('smtp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from smtplib import SMTP
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            s = SMTP(_ip, _port)
            s.ehlo()
            s.login(_username, _password)
            s.sendmail('fromtest', 'totest', 'Nothing')
            s.quit()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmtpserver = QSMTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qsmtpserver.run_server()
