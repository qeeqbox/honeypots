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
filterwarnings(action='ignore', module='.*paramiko.*')
filterwarnings(action='ignore', module='.*socket.*')

from paramiko import RSAKey, ServerInterface, Transport, OPEN_SUCCEEDED, AUTH_PARTIALLY_SUCCESSFUL, AUTH_SUCCESSFUL, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED, AUTH_FAILED
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, getfqdn
from _thread import start_new_thread
from io import StringIO
from random import choice
from subprocess import Popen
from os import path, getenv
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4
from contextlib import suppress
from re import compile as rcompile
from time import time
from threading import Event
from binascii import hexlify


class QSSHServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.mocking_server = choice(['OpenSSH 7.5', 'OpenSSH 7.3', 'Serv-U SSH Server 15.1.1.108', 'OpenSSH 6.4'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 22
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.ansi = rcompile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')

    def generate_pub_pri_keys(self):
        with suppress(Exception):
            key = RSAKey.generate(2048)
            string_io = StringIO()
            key.write_private_key(string_io)
            return key.get_base64(), string_io.getvalue()
        return None, None

    def ssh_server_main(self):
        _q_s = self

        class SSHHandle(ServerInterface):

            def __init__(self, ip, port):
                self.ip = ip
                self.port = port
                self.event = Event()
                # ServerInterface.__init__(self)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def check_channel_request(self, kind, chanid):
                if kind == 'session':
                    return OPEN_SUCCEEDED
                return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_auth_password(self, username, password):
                username = self.check_bytes(username)
                password = self.check_bytes(password)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                if status == 'success':
                    _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                    return AUTH_SUCCESSFUL
                _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                return AUTH_FAILED

            def check_channel_exec_request(self, channel, command):
                if "capture_commands" in _q_s.options:
                    _q_s.logs.info({'server': 'ssh_server', 'action': 'command', 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "data": {"command": self.check_bytes(command)}})
                self.event.set()
                return True

            def get_allowed_auths(self, username):
                return "password,publickey"

            def check_auth_publickey(self, username, key):
                _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "username": self.check_bytes(username), 'key_fingerprint': self.check_bytes(hexlify(key.get_fingerprint()))})
                return AUTH_SUCCESSFUL

            def check_channel_shell_request(self, channel):
                return True

            def check_channel_direct_tcpip_request(self, chanid, origin, destination):
                return OPEN_SUCCEEDED

            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                return True

        def ConnectionHandle(client, priv):
            with suppress(Exception):
                t = Transport(client)
                ip, port = client.getpeername()
                _q_s.logs.info({'server': 'ssh_server', 'action': 'connection', 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                t.local_version = 'SSH-2.0-' + _q_s.mocking_server
                t.add_server_key(RSAKey(file_obj=StringIO(priv)))
                sshhandle = SSHHandle(ip, port)
                t.start_server(server=sshhandle)
                conn = t.accept(30)
                if "interactive" in _q_s.options and conn is not None:
                    conn.send("Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.10.60.1-microsoft-standard-WSL2 x86_64)\r\n\r\n")
                    current_time = time()
                    while True and time() < current_time + 10:
                        conn.send("/$ ")
                        line = ""
                        while not line.endswith("\x0d") and not line.endswith("\x0a") and time() < current_time + 10:
                            conn.settimeout(10)
                            recv = conn.recv(1).decode()
                            conn.settimeout(None)
                            if _q_s.ansi.match(recv) is None and recv != "\x7f":
                                conn.send(recv)
                                line += recv
                        line = line.rstrip()
                        _q_s.logs.info({'server': 'ssh_server', 'action': 'interactive', 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "data": {"command": line}})
                        if line == "ls":
                            conn.send("\r\nbin cdrom etc lib lib64 lost+found mnt proc run snap swapfile tmp var boot dev home lib32 libx32 media opt root sbin srv sys usr\r\n")
                        elif line == "pwd":
                            conn.send("\r\n/\r\n")
                        elif line == "whoami":
                            conn.send("\r\nroot\r\n")
                        elif line == "exit":
                            break
                        else:
                            conn.send("\r\n{}: command not found\r\n".format(line))
                with suppress(Exception):
                    sshhandle.event.wait(2)
                with suppress(Exception):
                    conn.close()
                with suppress(Exception):
                    t.close()

        sock = socket(AF_INET, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock.bind((self.ip, self.port))
        sock.listen(1)
        pub, priv = self.generate_pub_pri_keys()
        while True:
            with suppress(Exception):
                client, addr = sock.accept()
                start_new_thread(ConnectionHandle, (client, priv,))

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

            self.logs.info({'server': 'ssh_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ssh_server_main()

    def close_port(self):
        ret = close_port_wrapper('ssh_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ssh_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        from paramiko import SSHClient, AutoAddPolicy
        _ip = ip or self.ip
        _port = port or self.port
        _username = username or self.username
        _password = password or self.password
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())  # if you have default ones, remove them before using this..
        ssh.connect(_ip, port=_port, username=_username, password=_password)


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsshserver = QSSHServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qsshserver.run_server()
