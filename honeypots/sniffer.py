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

from __future__ import annotations

import re
from binascii import hexlify
from multiprocessing import Process
from sys import stdout
from typing import Iterable, TYPE_CHECKING

from netifaces import AF_INET, AF_LINK, ifaddresses
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sniff

from honeypots.base_server import BaseServer
from honeypots.helper import server_arguments

ICMP_CODES = [
    (0, 0, "Echo/Ping reply"),
    (3, 0, "Destination network unreachable"),
    (3, 1, "Destination host unreachable"),
    (3, 2, "Destination protocol unreachable"),
    (3, 3, "Destination port unreachable"),
    (3, 4, "Fragmentation required"),
    (3, 5, "Source route failed"),
    (3, 6, "Destination network unknown"),
    (3, 7, "Destination host unknown"),
    (3, 8, "Source host isolated"),
    (3, 9, "Network administratively prohibited"),
    (3, 10, "Host administratively prohibited"),
    (3, 11, "Network unreachable for TOS"),
    (3, 12, "Host unreachable for TOS"),
    (3, 13, "Communication administratively prohibited"),
    (3, 14, "Host Precedence Violation"),
    (3, 15, "Precedence cutoff in effect"),
    (4, 0, "Source quench"),
    (5, 0, "Redirect Datagram for the Network"),
    (5, 1, "Redirect Datagram for the Host"),
    (5, 2, "Redirect Datagram for the TOS & network"),
    (5, 3, "Redirect Datagram for the TOS & host"),
    (8, 0, "Echo/Ping Request"),
    (9, 0, "Router advertisement"),
    (10, 0, "Router discovery/selection/solicitation"),
    (11, 0, "TTL expired in transit"),
    (11, 1, "Fragment reassembly time exceeded"),
    (12, 0, "Pointer indicates the error"),
    (12, 1, "Missing a required option"),
    (12, 2, "Bad length"),
    (13, 0, "Timestamp"),
    (14, 0, "Timestamp Reply"),
    (15, 0, "Information Request"),
    (16, 0, "Information Reply"),
    (17, 0, "Address Mask Request"),
    (18, 0, "Address Mask Reply"),
    (30, 0, "Information Request"),
]
TCP_SYN_FLAG = 0b10

if TYPE_CHECKING:
    from scapy.packet import Packet


class QSniffer(BaseServer):
    NAME = "sniffer"

    def __init__(self, filter_=None, interface=None, config="", **kwargs):
        super().__init__(config=config, **kwargs)
        self.current_ip = ifaddresses(interface)[AF_INET][0]["addr"].encode("utf-8")
        self.current_mac = ifaddresses(interface)[AF_LINK][0]["addr"].encode("utf-8")
        self.filter = filter_
        self.interface = interface
        self.method = "TCPUDP"
        self.allowed_ports = []
        self.allowed_ips = []
        self.common = re.compile(rb"pass|user|login")

    @staticmethod
    def find_icmp(type_, code):
        for icmp_type, icmp_code, msg_type in ICMP_CODES:
            if type_ == icmp_type and code == icmp_code:
                return msg_type
        return "None"

    @staticmethod
    def get_layers(packet: Packet) -> Iterable[str]:
        try:
            yield packet.name
            while packet.payload:
                packet = packet.payload
                yield packet.name
        except AttributeError:
            pass

    def server_main(self):
        try:
            sniff(filter=self.filter, iface=self.interface, prn=self.capture_logic)
        except PermissionError as error:
            self.logger.error(f"Could not start sniffer: {error}")

    def _get_payloads(self, layers: list[str], packet: Packet):
        hex_payloads, raw_payloads, _fields = {}, {}, {}
        for layer in layers:
            try:
                _fields[layer] = packet[layer].fields
                if "load" in _fields[layer]:
                    raw_payloads[layer] = _fields[layer]["load"]
                    hex_payloads[layer] = hexlify(_fields[layer]["load"])
                    if re.search(self.common, raw_payloads[layer]):
                        self.log(
                            {
                                "action": "creds_check",
                                "payload": raw_payloads[layer],
                            },
                        )
            except Exception as error:
                self._log_error(error, 1)
        return _fields, hex_payloads, raw_payloads

    def capture_logic(self, packet: Packet):
        _layers: list[str] = list(self.get_layers(packet))
        _fields, hex_payloads, raw_payloads = self._get_payloads(_layers, packet)

        try:
            if self.method == "ALL":
                try:
                    self.log(
                        {
                            "action": "all",
                            "layers": _layers,
                            "fields": _fields,
                            "payload": hex_payloads,
                        },
                    )
                except Exception as error:
                    self._log_error(error, 2)
            elif (
                self.method == "TCPUDP"
                and packet.haslayer("IP")
                and len(hex_payloads) > 0
                and packet["IP"].src != self.current_ip
            ):
                self._log_tcp_udp(packet, hex_payloads, raw_payloads)

            if (
                packet.haslayer("IP")
                and packet.haslayer("ICMP")
                and packet["IP"].src != self.current_ip
            ):
                self.log(
                    {
                        "action": "icmp",
                        "dest_ip": packet["IP"].src,
                        "dst_ip": packet["IP"].dst,
                        "ICMP_Code": packet["ICMP"].code,
                        "ICMP_Type": packet["ICMP"].type,
                        "ICMP_MSG": self.find_icmp(packet["ICMP"].type, packet["ICMP"].code),
                    },
                )

            if (
                packet.haslayer("IP")
                and packet.haslayer("TCP")
                and packet["IP"].src != self.current_ip
                and packet["TCP"].flags == TCP_SYN_FLAG
            ):
                self._handle_tcp_scan(packet, hex_payloads, raw_payloads)

        except Exception as error:
            self._log_error(error, 5)

        stdout.flush()

    def _handle_tcp_scan(self, packet: Packet, hex_payloads: dict, raw_payloads: dict):
        self.log(
            {
                "action": "tcpscan",
                "dest_ip": packet["IP"].src,
                "dest_port": packet["TCP"].sport,
                "dst_ip": packet["IP"].dst,
                "dst_port": packet["TCP"].dport,
                "raw_payload": raw_payloads,
                "payload": hex_payloads,
            },
        )
        ip_pkg = IP(dst=packet["IP"].src, src=packet["IP"].dst)
        tcp_pkg = TCP(
            dport=packet["TCP"].sport,
            sport=packet["TCP"].dport,
            ack=(packet["TCP"].seq + 1),
            flags="SA",
        )
        send(ip_pkg / tcp_pkg, verbose=False)

    def _log_tcp_udp(self, packet: Packet, hex_payloads: dict, raw_payloads: dict):
        for layer in ["TCP", "UDP"]:
            if packet.haslayer(layer):
                try:
                    self.log(
                        {
                            "action": f"{layer.lower()}payload",
                            "dest_ip": packet["IP"].src,
                            "dest_port": packet[layer].sport,
                            "dst_ip": packet["IP"].dst,
                            "dst_port": packet[layer].dport,
                            "raw_payload": raw_payloads,
                            "payload": hex_payloads,
                        },
                    )
                except Exception as error:
                    self._log_error(error, 3)

    def log(self, log_data: dict):
        log_data.update({"ip": self.current_ip, "mac": self.current_mac})
        self.logs.info([self.NAME, log_data])

    def _log_error(self, error: Exception, _id: int):
        self.logs.error(
            [
                "errors",
                {"error": f"capture_logic_{_id}", "type": f"error -> {error!r}"},
            ]
        )

    def run_sniffer(self, process=None):
        if process:
            self._server_process = Process(name="QSniffer_", target=self.server_main)
            self._server_process.start()
        else:
            self.server_main()


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qsniffer = QSniffer(
            filter_=parsed.filter, interface=parsed.interface, config=parsed.config
        )
        qsniffer.run_sniffer()
