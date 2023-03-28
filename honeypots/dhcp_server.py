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
filterwarnings(action='ignore', module='.*OpenSSL.*')
filterwarnings(action='ignore', module='.*socket.*')

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from time import time
from twisted.python import log as tlog
from struct import unpack
from socket import inet_aton
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QDHCPServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 67
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def dhcp_server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def payload(self, value, message):
                op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = unpack('1s1s1s1s4s2s2s4s4s4s4s16s', message[:44])
                #op, htype, hlen, hops, xid, secs, flags, ciaddr
                response = b'\x02\x01\x06\x00' + xid + b'\x00\x00\x00\x00\x00\x00\x00\x00'
                #yiaddr, siaddr, giaddr, chaddr
                response += inet_aton(_q_s.dhcp_ip_lease) + inet_aton(_q_s.dhcp_ip) + inet_aton('0.0.0.0') + chaddr
                #sname, file, magic
                response += b'\x00' * 64 + b'\x00' * 128 + b'\x63\x82\x53\x63'
                # options
                response += bytes([53, 1, value])
                response += bytes([54, 4]) + inet_aton(_q_s.dhcp_ip)
                response += bytes([1, 4]) + inet_aton(_q_s.subnet_mask)
                response += bytes([3, 4]) + inet_aton(_q_s.router)
                response += bytes([6, 4]) + inet_aton(_q_s.dns_server)
                response += bytes([51, 4]) + b'\x00\x00\xa8\xc0'  # lease
                response += b'\xff'
                return response

            def parse_options(self, raw):
                options = {}
                tag_name = None
                tag_size = None
                tag = ''
                for idx, b in enumerate(raw):
                    if tag_name is None:
                        tag_name = b
                    elif tag_name is not None and tag_size is None:
                        tag_size = b
                        tag = ''
                    else:
                        if tag_size:
                            tag_size -= 1
                            tag += chr(b)
                            if tag_size == 0:
                                options.update({self.check_bytes(tag_name): self.check_bytes(tag)})
                                tag_name = None
                                tag_size = None
                                tag = ''
                return options

            def datagramReceived(self, data, addr):
                mac_address = unpack('!28x6s', data[:34])[0].hex(':')
                data = self.parse_options(data[240:])
                data.update({'mac_address': mac_address})
                _q_s.logs.info({'server': 'dhcp_server', 'action': 'query', 'status': 'success', 'src_ip': addr[0], 'src_port': addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': data})
                self.transport.loseConnection()

        reactor.listenUDP(port=self.port, protocol=CustomDatagramProtocolProtocol(), interface=self.ip)
        reactor.run()

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
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'dhcp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.dhcp_server_main()

    def close_port(self):
        ret = close_port_wrapper('dhcp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('dhcp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None):
        pass


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qdhcpserver = QDHCPServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        qdhcpserver.run_server()
