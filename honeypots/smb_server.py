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
filterwarnings(action='ignore', module='.*impacket.*')

from logging import StreamHandler, getLogger, DEBUG
from impacket import smbserver
from tempfile import mkdtemp
from shutil import rmtree
from impacket.ntlm import compute_lmhash, compute_nthash
from logging import DEBUG, getLogger
from os import path
from subprocess import Popen
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4


class QSMBServer():
    def __init__(self, ip=None, port=None, username=None, password=None, folders=None, mocking=False, config=''):
        self.auto_disabled = None
        self.mocking = mocking or ''
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        self.ip = None
        self.port = None
        self.username = None
        self.password = None
        self.folders = None
        if config:
            self.logs = setup_logger(__class__.__name__, self.uuid, config)
            set_local_vars(self, config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = ip or self.ip or '0.0.0.0'
        self.port = port or self.port or 445
        self.username = username or self.username or 'test'
        self.password = password or self.password or 'test'
        self.folders = folders or self.folders or ''
        self.disable_logger()

    def disable_logger(self):
        getLogger('impacket').propagate = False

    def smb_server_main(self):
        _q_s = self

        class Logger(object):
            def write(self, message):
                #sys.stdout.write(str('>>>>' + message))
                # sys.stdout.flush()
                try:
                    if 'Incoming connection' in message.strip() or 'AUTHENTICATE_MESSAGE' in message.strip() or 'authenticated successfully' in message.strip():
                        _q_s.logs.info({'server': 'smb_server', 'action': 'connection', 'msg': message.strip()})
                    elif ':4141414141414141:' in message.strip():
                        parsed = message.strip().split(':')
                        if len(parsed) > 2:
                            _q_s.logs.info({'server': 'smb_server', 'action': 'login', 'workstation': parsed[0], 'test': parsed[1]})
                except Exception as e:
                    pass

        handler = StreamHandler(Logger())
        getLogger('impacket').addHandler(handler)
        getLogger('impacket').setLevel(DEBUG)

        dirpath = mkdtemp()
        server = smbserver.SimpleSMBServer(listenAddress=self.ip, listenPort=self.port)
        # server.removeShare('IPC$')
        if self.folders == '' or self.folders is None:
            server.addShare('C$', dirpath, '', readOnly='yes')
        else:
            for folder in self.folders.split(','):
                name, d = folder.split(':')
                if path.isdir(d) and len(name) > 0:
                    server.addShare(name, d, '', readOnly='yes')

        server.setSMB2Support(True)
        server.addCredential(self.username, 0, compute_lmhash(self.password), compute_nthash(self.password))
        server.setSMBChallenge('')
        server.start()
        rmtree(dirpath)

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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--folders', str(self.folders), '--mocking', str(self.mocking), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'smb_server', 'action': 'process', 'status': status, 'dest_ip': self.ip, 'dest_port': self.port, 'username': self.username, 'password': self.password, 'folders': str(self.folders)})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.smb_server_main()

    def close_port(self):
        ret = close_port_wrapper('smb_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('smb_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        try:
            from impacket.smbconnection import SMBConnection
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            smb_client = SMBConnection(_ip, _ip, sess_port=_port)
            smb_client.login(_username, _password)
        except Exception as e:
            pass


if __name__ == '__main__':

    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmbserver = QSMBServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, folders=parsed.folders, mocking=parsed.mocking, config=parsed.config)
        qsmbserver.run_server()
