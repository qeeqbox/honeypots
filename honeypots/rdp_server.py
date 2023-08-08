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

from socket import socket, SHUT_RDWR, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_NONE
from subprocess import Popen
from os import path, getenv
from honeypots.helper import check_if_server_is_running, close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, set_local_vars, setup_logger
from uuid import uuid4
from contextlib import suppress
from threading import Event, Thread
from binascii import hexlify
from struct import unpack
from OpenSSL import crypto
from tempfile import gettempdir, _get_candidate_names


class QRDPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.process = None
        self.key = path.join(gettempdir(), next(_get_candidate_names()))
        self.cert = path.join(gettempdir(), next(_get_candidate_names()))
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 3389
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''

    def rdp_server_main(self):
        _q_s = self

        def CreateCert(host_name, key, cert):
            pk = crypto.PKey()
            pk.generate_key(crypto.TYPE_RSA, 2048)
            c = crypto.X509()
            c.get_subject().C = 'US'
            c.get_subject().ST = 'OR'
            c.get_subject().L = 'None'
            c.get_subject().O = 'None'
            c.get_subject().OU = 'None'
            c.get_subject().CN = next(_get_candidate_names())
            c.set_serial_number(0)
            before, after = (0, 60 * 60 * 24 * 365 * 2)
            c.gmtime_adj_notBefore(before)
            c.gmtime_adj_notAfter(after)
            c.set_issuer(c.get_subject())
            c.set_pubkey(pk)
            c.sign(pk, 'sha256')
            open(cert, 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, c))
            open(key, 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk))

        class ConnectionHandle(Thread):
            def __init__(self, sock, key, cert):
                super(ConnectionHandle, self).__init__()
                self.sock = sock
                self.key = key
                self.cert = cert

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def get_value(self, length, data):
                with suppress(Exception):
                    var = b''
                    for idx, _ in enumerate(data):
                        if _ == 0 and data[idx + 1] == 0:
                            break
                        if _ == 0:
                            continue
                        else:
                            var += bytes([_])
                    if length / 2 == len(var):
                        return var
                return b''

            def extract_cookie(self, data):
                cookie = b''
                with suppress(Exception):
                    for idx, _ in enumerate(data):
                        if _ == 13 and data[idx + 1] == 10:
                            break
                        else:
                            cookie += bytes([_])
                return cookie

            def extract_creds(self, data):
                user = ''
                password = ''
                with suppress(Exception):
                    flag, flags, code_page, option_flags, domain_length, user_length, password_length, shell_length, working_dir_length = unpack('HHIIHHHHH', data[15:37])
                    location = 37
                    domain = self.get_value(domain_length, data[location:])
                    location = location + domain_length + 2
                    user = self.get_value(user_length, data[location:])
                    location = location + user_length + 2
                    password = self.get_value(password_length, data[location:])
                    location = location + password_length + 2
                    shell = self.get_value(shell_length, data[location:])
                    location = location + shell_length + 2
                    working_dir = self.get_value(working_dir_length, data[location:])
                return user, password

            def run(self):
                # There is no good documentation on how RDP protocol works (It took a bit of time to figure it out - Use b1105eb1-d1f7-414b-ad68-fd0c5a7823e4 test case)
                cookie = ''
                rdpdr = False
                cliprdr = False
                rdpsnd = False
                initiator = b'\x00\x06'
                with suppress(Exception):
                    _q_s.logs.info({'server': 'rdp_server', 'action': 'connection', 'src_ip': self.sock.getpeername()[0], 'src_port': self.sock.getpeername()[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                    # Client X.224 Connection Request PDU

                    data = self.sock.recv(1024)
                    if b'Cookie' in data:
                        cookie = self.extract_cookie(data[11:])
                        cookie = self.check_bytes(cookie)
                        _q_s.logs.info({'server': 'rdp_server', 'action': 'stshash', 'mstshash': 'success', 'src_ip': self.sock.getpeername()[0], 'src_port': self.sock.getpeername()[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': {'stshash': cookie}})

                    # Server X.224 Connection Confirm PDU
                    # data[0] version
                    # 19 (x13) total len
                    # 14 (x0e) X.224 len
                    # TLS only \x02\x00\x08\x00\x01\x00\x00\x00

                    self.sock.send(b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x01\x00\x00\x00')
                    ctx = SSLContext(PROTOCOL_TLSv1_2)
                    ctx.set_ciphers('RSA:!aNULL')
                    ctx.check_hostname = False
                    ctx.verify_mode = CERT_NONE
                    ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
                    self.sock = ctx.wrap_socket(self.sock, server_side=True, do_handshake_on_connect=True)

                    data = self.sock.recv(1024)

                    if b'rdpdr' in data:
                        rdpdr = True
                    if b'cliprdr' in data:
                        cliprdr = True
                    if b'rdpsnd' in data:
                        rdpsnd = True

                    # MCS Connect Response PDU with GCC Conference Create Response
                    # \x03\x00\x00
                    # \x7c
                    # \x02\xf0\x80\x7f\x66\x74\x0a\x01\x00\x02\x01\x00\x30\x1a\x02\x01\x22\x02\x01\x03\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xf8\x02\x01\x02\x04
                    # \x4e
                    # \x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0\x00\x4d\x63\x44\x6e
                    # \x38
                    # \x01\x0c SC_CORE
                    # \x0e\x00\x04\x00\x08\x00\x03\x00\x00\x00\x03\x00
                    # \x02\x0c SC_SECURITY
                    # \x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00
                    # \x03\x0c SC_NET
                    # 03eb I/O channel
                    # 03ec rdpdr channel
                    # 03ed cliprdr channel
                    # 03ef rdpsnd channel
                    # \x10\x00\xeb\x03\x04\x00\xec\x03\xed\x03\xee\x03\xef\x03
                    # \x04\x0c SC_MCS_MSGCHANNEL
                    # \x06\x00\xf0\x03
                    # \x08\x0c SC_MULTITRANSPORT
                    # \x08\x00\x00\x00\x00\x00

                    self.sock.send(b'\x03\x00\x00\x7c\x02\xf0\x80\x7f\x66\x74\x0a\x01\x00\x02\x01\x00\x30\x1a\x02\x01\x22\x02\x01\x03\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xf8\x02\x01\x02\x04\x4e\x00\x05\x00\x14\x7c\x00\x01\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0\x00\x4d\x63\x44\x6e\x38\x01\x0c\x0e\x00\x04\x00\x08\x00\x03\x00\x00\x00\x03\x00\x02\x0c\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x0c\x10\x00\xeb\x03\x04\x00\xec\x03\xed\x03\xee\x03\xef\x03\x04\x0c\x06\x00\xf0\x03\x08\x0c\x08\x00\x00\x00\x00\x00')

                    data = self.sock.recv(1024)
                    data = self.sock.recv(1024)

                    # Server MCS Attach-User Confirm PDU
                    # 03 00 00 0b 02 f0 80 2e 00 00 06
                    self.sock.send(b'\x03\x00\x00\x0b\x02\xf0\x80\x2e\x00' + initiator)

                    # Multiple channel join
                    # 03 00 00 0c 02 f0 80 38 00 06 03 eb
                    # 03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb

                    with suppress(Exception):
                        # 7 times + 1
                        for i in range(8):
                            data = self.sock.recv(1024)
                            if len(data) > 14:
                                if data[15] == 64:
                                    username = ''
                                    password = ''
                                    status = 'failed'
                                    username, password = self.extract_creds(data)
                                    username = self.check_bytes(username)
                                    password = self.check_bytes(password)
                                    if username == _q_s.username and password == _q_s.password:
                                        username = _q_s.username
                                        password = _q_s.password
                                        status = 'success'
                                    _q_s.logs.info({'server': 'rdp_server', 'action': 'login', 'status': status, 'src_ip': self.sock.getpeername()[0], 'src_port': self.sock.getpeername()[1], 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                                    break
                            else:
                                self.sock.send(b'\x03\x00\x00\x0f\x02\xf0\x80\x3e\x00' + initiator + b'\x03' + bytes([data[-1]]) + b'\x03' + bytes([data[-1]]))

                    # MCS Disconnect Provider Ultimatum PDU
                    self.sock.send(b'\x03\x00\x00\x09\x02\xf0\x80\x21\x80')

                with suppress(Exception):
                    self.sock.shutdown(SHUT_RDWR)
                with suppress(Exception):
                    self.sock.close()

        CreateCert('localhost', self.key, self.cert)
        rpdserver = socket(AF_INET, SOCK_STREAM)
        rpdserver.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        rpdserver.bind((self.ip, self.port))
        rpdserver.listen()

        while True:
            with suppress(Exception):
                client, addr = rpdserver.accept()
                client.settimeout(10.0)
                ConnectionHandle(client, self.key, self.cert).start()

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

            self.logs.info({'server': 'rdp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.rdp_server_main()

    def close_port(self):
        ret = close_port_wrapper('rdp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('rdp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None):
        with suppress(Exception):
            from warnings import filterwarnings
            filterwarnings(action='ignore', module='.*socket.*')
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.sendto(b'test', (_ip, _port))
            c.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qrdpserver = QRDPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qrdpserver.run_server()
