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

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*impacket.*')

from logging import StreamHandler, getLogger, DEBUG
from impacket import smbserver
from impacket.smbconnection import SMBConnection
from tempfile import mkdtemp
from shutil import rmtree
from impacket.ntlm import compute_lmhash, compute_nthash
from time import sleep
from logging import DEBUG, getLogger
from os import path
from subprocess import Popen
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, set_local_vars
from uuid import uuid4

#loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
#print([logging.getLogger(name) for name in logging.root.manager.loggerDict])


class QSMBServer():
    def __init__(self, ip=None, port=None, username=None, password=None, mocking=False, config=''):
        self.auto_disabled = None
        self.ip = ip or '0.0.0.0'
        self.port = port or 445
        self.username = username or "test"
        self.password = password or "test"
        self.mocking = mocking or ''
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(self.uuid, None)
        self.disable_logger()

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
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                    if self.process.poll() is None:
                        self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                    else:
                        self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'setup', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
            elif self.close_port() and self.kill_server():
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'success', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
                else:
                    self.logs.info(["servers", {'server': 'smb_server', 'action': 'process', 'status': 'error', 'ip': self.ip, 'port': self.port, 'username': self.username, 'password': self.password}])
        else:
            self.smb_server_main()

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
        ret = close_port_wrapper('smb_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('smb_server', self.uuid, self.process)
        return ret


if __name__ == '__main__':

    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmbserver = QSMBServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, mocking=parsed.mocking, config=parsed.config)
        qsmbserver.run_server()
