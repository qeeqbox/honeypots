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
filterwarnings(action='ignore', module='.*scapy.*')

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from scapy.all import SNMP
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QSNMPServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 161
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def snmp_server_main(self):
        _q_s = self

        class CustomDatagramProtocolProtocol(DatagramProtocol):
            def parse_snmp(self, data):
                version = 'UnKnown'
                community = 'UnKnown'
                oids = 'UnKnown'
                with suppress(Exception):
                    parsed_snmp = SNMP(data)
                    community = parsed_snmp.community.val
                    version = parsed_snmp.version.val
                    oids = ' '.join([item.oid.val for item in parsed_snmp.PDU.varbindlist])
                return version, community, oids

            def datagramReceived(self, data, addr):
                _q_s.logs.info({'server': 'snmp_server', 'action': 'connection', 'status': 'fail', 'src_ip': addr[0], 'src_port': addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                version, community, oids = self.parse_snmp(data)
                if version or community or oids:
                    _q_s.logs.info({'server': 'snmp_server', 'action': 'query', 'status': 'success', 'src_ip': addr[0], 'src_port': addr[1], 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': {'version': version, 'community': community, 'oids': oids}})
                    self.transport.write('Error', addr)

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

            self.logs.info({'server': 'snmp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.snmp_server_main()

    def close_port(self):
        ret = close_port_wrapper('snmp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('snmp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from pysnmp.hlapi import (getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,)
            _ip = ip or self.ip
            _port = port or self.port
            g = getCmd(SnmpEngine(), CommunityData('public'), UdpTransportTarget((_ip, _port)), ContextData(), ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.618.1.4.1.0')))
            errorIndication, errorStatus, errorIndex, varBinds = next(g)


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QSNMPServer = QSNMPServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        QSNMPServer.run_server()
