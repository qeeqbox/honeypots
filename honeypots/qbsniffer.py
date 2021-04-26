__G__ = "(G)bd249ce4"

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*scapy.*')

from scapy.all import *
from sys import stdout
from binascii import hexlify
from netifaces import ifaddresses, AF_INET, AF_LINK
from binascii import hexlify
from multiprocessing import Process
from re import search as rsearch
from re import compile as rcompile
from honeypots.helper import server_arguments, setup_logger
from uuid import uuid4


class QBSniffer():
    def __init__(self, filter=None, interface=None, config=''):
        self.current_ip = ifaddresses(interface)[AF_INET][0]['addr'].encode('utf-8')
        self.current_mac = ifaddresses(interface)[AF_LINK][0]['addr'].encode('utf-8')
        self.filter = filter
        self.interface = interface
        self.method = "TCPUDP"
        self.ICMP_codes = [(0, 0, 'Echo/Ping reply'), (3, 0, 'Destination network unreachable'), (3, 1, 'Destination host unreachable'), (3, 2, 'Desination protocol unreachable'), (3, 3, 'Destination port unreachable'), (3, 4, 'Fragmentation required'), (3, 5, 'Source route failed'), (3, 6, 'Destination network unknown'), (3, 7, 'Destination host unknown'), (3, 8, 'Source host isolated'), (3, 9, 'Network administratively prohibited'), (3, 10, 'Host administratively prohibited'), (3, 11, 'Network unreachable for TOS'), (3, 12, 'Host unreachable for TOS'), (3, 13, 'Communication administratively prohibited'), (3, 14, 'Host Precedence Violation'), (3, 15, 'Precendence cutoff in effect'), (4, 0, 'Source quench'),
                           (5, 0, 'Redirect Datagram for the Network'), (5, 1, 'Redirect Datagram for the Host'), (5, 2, 'Redirect Datagram for the TOS & network'), (5, 3, 'Redirect Datagram for the TOS & host'), (8, 0, 'Echo/Ping Request'), (9, 0, 'Router advertisement'), (10, 0, 'Router discovery/selection/solicitation'), (11, 0, 'TTL expired in transit'), (11, 1, 'Fragment reassembly time exceeded'), (12, 0, 'Pointer indicates the error'), (12, 1, 'Missing a required option'), (12, 2, 'Bad length'), (13, 0, 'Timestamp'), (14, 0, 'Timestamp Reply'), (15, 0, 'Information Request'), (16, 0, 'Information Reply'), (17, 0, 'Address Mask Request'), (18, 0, 'Address Mask Reply'), (30, 0, 'Information Request')]
        self.allowed_ports = []
        self.allowed_ips = []
        self.common = rcompile(rb'pass|user|login')
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = config
        if config:
            self.logs = setup_logger(self.uuid, config)
        else:
            self.logs = setup_logger(self.uuid, None)

    def find_ICMP(self, x1, x2):
        for _ in self.ICMP_codes:
            if x1 == _[0] and x2 == _[1]:
                return _[2]
        return "None"

    def get_layers(self, packet):
        try:
            yield packet.name
            while packet.payload:
                packet = packet.payload
                yield packet.name
        except BaseException:
            pass

    def scapy_sniffer_main(self):
        _q_s = self

        def capture_logic(packet):
            _layers, hex_payloads, raw_payloads, _fields, _raw, _hex = [], {}, {}, {}, 'None', 'None'
            _layers = list(self.get_layers(packet))
            for layer in _layers:
                try:
                    _fields[layer] = packet[layer].fields
                    if "load" in _fields[layer]:
                        raw_payloads[layer] = _fields[layer]["load"]
                        hex_payloads[layer] = hexlify(_fields[layer]["load"])
                        if rsearch(self.common, raw_payloads[layer]):
                            _q_s.logs.info(["sniffer", {'action': 'creds_check', "payload": raw_payloads[layer]}])
                except Exception as e:
                    print(e)
                    _q_s.logs.error(["errors", {'error': 'capture_logic_1', "type": "error -> " + repr(e)}])

            try:
                if _q_s.method == "ALL":
                    try:
                        _q_s.logs.info(["sniffer", {'action': 'all', 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'layers': _layers, 'fields': _fields, "payload": hex_payloads}])
                    except Exception as e:
                        _q_s.logs.error(["errors", {'error': 'capture_logic_2', "type": "error -> " + repr(e)}])
                elif _q_s.method == "TCPUDP":
                    if packet.haslayer('IP') and len(hex_payloads) > 0 and packet['IP'].src != _q_s.current_ip:
                        if packet.haslayer('TCP'):
                            try:
                                _q_s.logs.info(["sniffer", {'action': 'tcppayload', 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'src_ip': packet['IP'].src, 'src_port':packet['TCP'].sport, 'dst_ip':packet['IP'].dst, 'dst_port':packet['TCP'].dport, "raw_payload":raw_payloads, "payload":hex_payloads}])
                            except Exception as e:
                                _q_s.logs.error(["errors", {'error': 'capture_logic_3', "type": "error -> " + repr(e)}])
                        elif packet.haslayer('UDP'):
                            try:
                                _q_s.logs.info(["sniffer", {'action': 'udppayload', 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'src_ip': packet['IP'].src, 'src_port':packet['UDP'].sport, 'dst_ip':packet['IP'].dst, 'dst_port':packet['UDP'].dport, "raw_payload":raw_payloads, "payload":hex_payloads}])
                            except Exception as e:
                                _q_s.logs.error(["errors", {'error': 'capture_logic_4', "type": "error -> " + repr(e)}])

                if packet.haslayer('IP') and packet.haslayer('ICMP') and packet['IP'].src != _q_s.current_ip:
                    _q_s.logs.info(["sniffer", {'action': 'icmp', 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'src_ip': packet['IP'].src, 'dst_ip':packet['IP'].dst, 'ICMP_Code':packet['ICMP'].code, 'ICMP_Type':packet['ICMP'].type, 'ICMP_MSG':self.find_ICMP(packet['ICMP'].type, packet['ICMP'].code)}])

                if packet.haslayer('IP') and packet.haslayer('TCP') and packet['IP'].src != _q_s.current_ip:
                    if packet['TCP'].flags == 2:
                        _q_s.logs.info(["sniffer", {'action': 'tcpscan', 'ip': _q_s.current_ip, 'mac': _q_s.current_mac, 'src_ip': packet['IP'].src, 'src_port':packet['TCP'].sport, 'dst_ip':packet['IP'].dst, 'dst_port':packet['TCP'].dport, "raw_payload":raw_payloads, "payload":hex_payloads}])
                        send(IP(dst=packet['IP'].src, src=packet['IP'].dst) / TCP(dport=packet['TCP'].sport, sport=packet['TCP'].dport, ack=(packet['TCP'].seq + 1), flags='SA'), verbose=False)

            except Exception as e:
                _q_s.logs.error(["errors", {'error': 'capture_logic_5', "type": "error -> " + repr(e)}])

            stdout.flush()

        sniff(filter=self.filter, iface=self.interface, prn=capture_logic)

    def run_sniffer(self, process=None):
        if process:
            self.process = Process(name='QSniffer_', target=self.scapy_sniffer_main)
            self.process.start()
        else:
            self.scapy_sniffer_main()

    def kill_sniffer(self):
        self.process.terminate()
        self.process.join()


if __name__ == "__main__":
    from server_options import server_arguments
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsniffer = QSniffer(filter=parsed.filter, interface=parsed.interface, config=parsed.config)
        qsniffer.run_sniffer()
