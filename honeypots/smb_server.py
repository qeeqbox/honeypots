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
from time import sleep
from impacket.ntlm import compute_lmhash, compute_nthash
from logging import DEBUG, getLogger
from os import path, getenv
from subprocess import Popen
from six.moves import configparser, socketserver
from threading import enumerate as threading_enumerate
from random import randint
from threading import current_thread
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4
from contextlib import suppress


class QSMBServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.folders = ''
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 445
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.disable_logger()

    def disable_logger(self):
        getLogger('impacket').propagate = False

    def smb_server_main(self):
        _q_s = self

        class Logger(object):
            def write(self, message):
                with suppress(Exception):
                    temp = current_thread().name
                    if temp.startswith('thread_'):
                        ip = temp.split('_')[1]
                        port = temp.split('_')[2]
                        if 'Incoming connection' in message.strip() or 'AUTHENTICATE_MESSAGE' in message.strip() or 'authenticated successfully' in message.strip():
                            _q_s.logs.info({'server': 'smb_server', 'action': 'connection', 'data': message.strip(), 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                        elif ':4141414141414141:' in message.strip():
                            parsed = message.strip().split(':')
                            if len(parsed) > 2:
                                _q_s.logs.info({'server': 'smb_server', 'action': 'login', 'workstation': parsed[0], 'test': parsed[1], 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

        class SMBSERVERHandler(smbserver.SMBSERVERHandler):
            def __init__(self, request, client_address, server, select_poll=False):
                self.__SMB = server
                self.__timeOut = 60 * 10
                self.__request = request
                self.__select_poll = select_poll
                self.__ip, self.__port = client_address[:2]
                self.__connId = "thread_{}_{}_{}".format(self.__ip, self.__port, randint(1000, 9999))
                current_thread().name = self.__connId
                socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

        class SMBSERVER(smbserver.SMBSERVER):
            def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser=None):
                super().__init__(server_address, handler_class, config_parser)

            def processRequest(self, connId, data):
                x = super().processRequest(connId, data)
                return x

        class SimpleSMBServer(smbserver.SimpleSMBServer):
            def __init__(self, listenAddress='0.0.0.0', listenPort=445, configFile=''):
                super().__init__(listenAddress, listenPort, configFile)
                self.__server.server_close()
                sleep(randint(1, 2))
                self.__server = SMBSERVER((listenAddress, listenPort), config_parser=self.__smbConfig)
                self.__server.processConfigFile()

            def start(self):
                self.__srvsServer.start()
                self.__wkstServer.start()
                self.__server.serve_forever()

        handler = StreamHandler(Logger())
        getLogger('impacket').addHandler(handler)
        getLogger('impacket').setLevel(DEBUG)

        dirpath = mkdtemp()
        server = SimpleSMBServer(listenAddress=self.ip, listenPort=self.port)
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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'smb_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

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
        with suppress(Exception):
            from impacket.smbconnection import SMBConnection
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            smb_client = SMBConnection(_ip, _ip, sess_port=_port)
            smb_client.login(_username, _password)


if __name__ == '__main__':

    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsmbserver = QSMBServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, folders=parsed.folders, options=parsed.options, config=parsed.config)
        qsmbserver.run_server()
