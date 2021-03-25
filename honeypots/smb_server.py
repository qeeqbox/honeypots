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
filterwarnings(action='ignore', category=DeprecationWarning)

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*impacket.*')

from logging import StreamHandler, getLogger, DEBUG
from impacket import smbserver
from impacket.smbconnection import SMBConnection
from tempfile import mkdtemp
from shutil import rmtree
from impacket.ntlm import compute_lmhash, compute_nthash
from multiprocessing import Process
from psutil import process_iter
from signal import SIGTERM
from time import sleep
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from os import path
from socket import socket as ssocket
from socket import AF_INET, SOCK_STREAM
from subprocess import Popen
from tempfile import gettempdir, _get_candidate_names
from honeypots.helper import server_arguments, get_free_port, CustomHandler
from uuid import uuid4

#loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
#print([logging.getLogger(name) for name in logging.root.manager.loggerDict])


class QSMBServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, logs=None):
        self.ip = ip or '0.0.0.0'
        self.port = port or 445
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.process = None
        self._logs = logs
        self.setup_logger(self._logs)
        self.disable_logger()

    def setup_logger(self, logs):
        self.logs = getLogger('honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8])
        self.logs.setLevel(DEBUG)
        self.logs.addHandler(CustomHandler())

    def disable_logger(self):
        getLogger('impacket').propagate = False

    def smb_server_main(self):
        _q_s = self

        class Logger(object):
            def write(self, message):
                #sys.stdout.write(str(">>>>" + message))
                # sys.stdout.flush()
                try:
                    if "Incoming connection" in message.strip() or "AUTHENTICATE_MESSAGE" in message.strip() or "authenticated successfully" in message.strip():
                        _q_s.logs.info(["servers", {'server': 'smb_server', 'action': 'connection', 'msg': message.strip()}])
                    elif ":4141414141414141:" in message.strip():
                        parsed = message.strip().split(":")
                        if len(parsed) > 2:
                            _q_s.logs.info(["servers", {'server': 'smb_server', 'action': 'login', 'workstation': parsed[0], 'test':parsed[1]}])
                except Exception as e:
                    _q_s.logs.error(["errors", {'server': 'smb_server', 'error': 'write', "type": "error -> " + repr(e)}])

        handler = StreamHandler(Logger())
        getLogger("impacket").addHandler(handler)
        getLogger("impacket").setLevel(DEBUG)

        dirpath = mkdtemp()
        server = smbserver.SimpleSMBServer(listenAddress=self.ip, listenPort=self.port)
        # server.removeShare("IPC$")
        server.addShare('C$', dirpath, '', readOnly='yes')
        server.setSMB2Support(True)
        server.addCredential(self.username, 0, compute_lmhash(self.password), compute_nthash(self.password))
        server.setSMBChallenge('')
        server.start()
        rmtree(dirpath)

    def run_server(self, process=False, auto=False):
        if process:
            if auto:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--logs', str(self._logs)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--logs', str(self._logs)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.smb_server_main()

    def kill_server(self, process=False):
        try:
            self.process.kill()
            for process in process_iter():
                cmdline = ' '.join(process.cmdline())
                if '--custom' in cmdline and Path(__file__).name in cmdline:
                    process.send_signal(SIGTERM)
                    process.kill()
            if self.process is not None:
                self.process.kill()
            return True
        except BaseException:
            pass
        return False

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            sleep(2)
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            smb_client = SMBConnection(_ip, _ip, sess_port=_port)
            smb_client.login(_username, _password)
        except Exception as e:
            self.logs.error(["errors", {'server': 'smb_server', 'error': 'write', "type": "error -> " + repr(e)}])

    def close_port(self):
        sock = ssocket(AF_INET, SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((self.ip, self.port)) == 0:
            for process in process_iter():
                try:
                    for conn in process.connections(kind='inet'):
                        if self.port == conn.laddr.port:
                            process.send_signal(SIGTERM)
                            process.kill()
                except BaseException:
                    pass
        if sock.connect_ex((self.ip, self.port)) != 0:
            return True
        else:
            self.logs.error(['errors', {'server': 'smb_server', 'error': 'port_open', 'type': 'Port {} still open..'.format(self.ip)}])
            return False


if __name__ == '__main__':

    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmbserver = QSMBServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, logs=parsed.logs)
        qsmbserver.run_server()
