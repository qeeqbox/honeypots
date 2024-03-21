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

from contextlib import suppress
import struct

from twisted.internet import reactor
from twisted.web.resource import Resource
from twisted.web.server import Site

from honeypots.base_server import BaseServer
from honeypots.helper import (
    server_arguments,
    check_bytes,
    get_headers_and_ip_from_request,
)

SUPPORTED_OPERATIONS = {
    0x0001: "Reserved",
    0x0002: "Print-Job",
    0x0003: "Print-URI",
    0x0004: "Validate-Job",
    0x0005: "Create-Job",
    0x0006: "Send-Document",
    0x0007: "Send-URI",
    0x0008: "Cancel-Job",
    0x0009: "Get-Job-Attributes",
    0x000A: "Get-Jobs",
    0x000B: "Get-Printer-Attributes",
    0x000C: "Hold-Job",
    0x000D: "Release-Job",
    0x000E: "Restart-Job",
    0x000F: "Reserved",
    0x0010: "Pause-Printer",
    0x0011: "Resume-Printer",
    0x0012: "Purge-Jobs",
    0x0013: "Set-Printer-Attributes",
    0x0014: "Set-Job-Attributes",
    0x0015: "Get-Printer-Supported-Values",
    0x0016: "Create-Printer-Subscriptions",
    0x0017: "Create-Job-Subscriptions",
    0x0018: "Get-Subscription-Attributes",
    0x0019: "Get-Subscriptions",
    0x001A: "Renew-Subscription",
    0x001B: "Cancel-Subscription",
    0x001C: "Get-Notifications",
    0x001D: "ipp-indp-method",
    0x001E: "Get-Resource-Attributes",
    0x001F: "ipp-get-resources",
    0x0020: "Get-Resources",
    0x0021: "ipp-install",
    0x0022: "Enable-Printer",
    0x0023: "Disable-Printer",
    0x0024: "Pause-Printer-After-Current-Job",
    0x0025: "Hold-New-Jobs",
    0x0026: "Release-Held-New-Jobs",
    0x0027: "Deactivate-Printer",
    0x0028: "Activate-Printer",
    0x0029: "Restart-Printer",
    0x002A: "Shutdown-Printer",
    0x002B: "Startup-Printer",
    0x002C: "Reprocess-Job",
    0x002D: "Cancel-Current-Job",
    0x002E: "Suspend-Current-Job",
    0x002F: "Resume-Job",
    0x0030: "Promote-Job",
    0x0031: "Schedule-Job-After",
    0x0033: "Cancel-Document",
    0x0034: "Get-Document-Attributes",
    0x0035: "Get-Documents",
    0x0036: "Delete-Document",
    0x0037: "Set-Document-Attributes",
    0x0038: "Cancel-Jobs",
    0x0039: "Cancel-My-Jobs",
    0x003A: "Resubmit-Job",
    0x003B: "Close-Job",
    0x003C: "Identify-Printer",
    0x003D: "Validate-Document",
    0x003E: "Add-Document-Images",
    0x003F: "Acknowledge-Document",
    0x0040: "Acknowledge-Identify-Printer",
    0x0041: "Acknowledge-Job",
    0x0042: "Fetch-Document",
    0x0043: "Fetch-Job",
    0x0044: "Get-Output-Device-Attributes",
    0x0045: "Update-Active-Jobs",
    0x0046: "Deregister-Output-Device",
    0x0047: "Update-Document-Status",
    0x0048: "Update-Job-Status",
    0x0049: "Update-Output-Device-Attributes",
    0x004A: "Get-Next-Document-Data",
    0x004B: "Allocate-Printer-Resources",
    0x004C: "Create-Printer",
    0x004D: "Deallocate-Printer-Resources",
    0x004E: "Delete-Printer",
    0x004F: "Get-Printers",
    0x0050: "Shutdown-One-Printer",
    0x0051: "Startup-One-Printer",
    0x0052: "Cancel-Resource",
    0x0053: "Create-Resource",
    0x0054: "Install-Resource",
    0x0055: "Send-Resource-Data",
    0x0056: "Set-Resource-Attributes",
    0x0057: "Create-Resource-Subscriptions",
    0x0058: "Create-System-Subscriptions",
    0x0059: "Disable-All-Printers",
    0x005A: "Enable-All-Printers",
    0x005B: "Get-System-Attributes",
    0x005C: "Get-System-Supported-Values",
    0x005D: "Pause-All-Printers",
    0x005E: "Pause-All-Printers-After-Current-Job",
    0x005F: "Register-Output-Device",
    0x0060: "Restart-System",
    0x0061: "Resume-All-Printers",
    0x0062: "Set-System-Attributes",
    0x0063: "Shutdown-All-Printers",
    0x0064: "Startup-All-Printers",
    0x0065: "Get-Printer-Resources",
    0x0066: "Get-User-Printer-Attributes",
    0x0067: "Restart-One-Printer",
}
ATTRIBUTE_GROUP_TAGS = {
    0x00: "Reserved",
    0x01: "operation-attributes-tag",
    0x02: "job-attributes-tag",
    0x03: "end-of-attributes-tag",
    0x04: "printer-attributes-tag",
    0x05: "unsupported-attributes-tag",
    0x06: "subscription-attributes-tag",
    0x07: "event-notification-attributes-tag",
    0x08: "resource-attributes-tag",
    0x09: "document-attributes-tag",
    0x0A: "system-attributes-tag",
}
ATTRIBUTE_SYNTAXES = {
    0x20: "Unassigned",
    0x21: "integer",
    0x22: "boolean",
    0x23: "enum",
    0x30: "octetString",
    0x31: "dateTime",
    0x32: "resolution",
    0x33: "rangeOfInteger",
    0x34: "begCollection",
    0x35: "textWithLanguage",
    0x36: "nameWithLanguage",
    0x37: "endCollection",
    0x40: "Unassigned",
    0x41: "textWithoutLanguage",
    0x42: "nameWithoutLanguage",
    0x43: "Unassigned",
    0x44: "keyword",
    0x45: "uri",
    0x46: "uriScheme",
    0x47: "charset",
    0x48: "naturalLanguage",
    0x49: "mimeMediaType",
    0x4A: "memberAttrName",
    0x7F: "extension",
}
ATTRIBUTE_NAME_TO_VALUE_TAG = {
    "attributes-charset": b"\x47",
    "attributes-natural-language": b"\x48",
}
STATUS_CODE_OK = b"\x00\x00"
STATUS_CODE_BAD_REQUEST = b"\x04\x00"


class QIPPServer(BaseServer):
    NAME = "ipp_server"
    DEFAULT_PORT = 631

    def server_main(self):  # noqa: C901
        _q_s = self

        class MainResource(Resource):
            isLeaf = True  # noqa: N815

            def render_POST(self, request):  # noqa: N802
                client_ip, headers = get_headers_and_ip_from_request(request, _q_s.options)

                log_data = {
                    "action": "connection",
                    "src_ip": client_ip,
                    "src_port": request.getClientAddress().port,
                }
                if "capture_commands" in _q_s.options:
                    log_data["data"] = headers
                _q_s.log(log_data)

                data = request.content.read()

                response, status = self._build_response(data)

                if len(response) > 0:
                    _q_s.log(
                        {
                            "action": "query",
                            "status": status,
                            "src_ip": client_ip,
                            "src_port": request.getClientAddress().port,
                            "data": {"request": response},
                        }
                    )
                return self.send_response(data, status != "failed")

            def _build_response(self, data: bytes) -> tuple[str, str]:
                status = "success"
                version = [0, 0]
                groups = []

                try:
                    index, version[0] = get_uint8_t(0, data)
                    index, version[1] = get_uint8_t(index, data)
                    index, uint16_t = get_uint16_t(index, data)
                    operation = SUPPORTED_OPERATIONS[uint16_t]
                    index, request_id = get_uint32_t(index, data)
                    index, uint8_t = get_uint8_t(index, data)
                    group = ATTRIBUTE_GROUP_TAGS[uint8_t]
                    index, uint8_t = get_uint8_t(index, data)
                    if uint8_t in ATTRIBUTE_SYNTAXES:
                        groups, status = self._parse_attributes(data, index, uint8_t)

                    response = (
                        f"VERSION {version[0]}.{version[1]}|"
                        f"REQUEST {hex(request_id)}|"
                        f"OPERATION {operation}|"
                        f"GROUP {group}|"
                    )
                    if len(groups) > 0:
                        for attribute, values in groups:
                            response += f"ATTR {attribute} {','.join(values)}|"
                    with suppress(IndexError):
                        if response[-1] == "|":
                            response = response[:-1]
                except Exception as error:
                    _q_s.logger.debug(
                        f"[{_q_s.NAME}]: An error occurred during data parsing: {error}",
                        exc_info=True,
                    )
                    response = ""
                return response, status

            @staticmethod
            def _parse_attributes(
                data: bytes, index: int, attr_type: int
            ) -> tuple[list[tuple[str, list[str]]], str]:
                status = "success"
                groups = []
                to_parse_len = len(data[index:])
                while index < to_parse_len:
                    try:
                        value = ""
                        if ATTRIBUTE_SYNTAXES[attr_type] == "integer":
                            index, attribute = get_uint32_t(index, data)
                        elif ATTRIBUTE_SYNTAXES[attr_type] == "boolean":
                            index, attribute = get_uint8_t(index, data)
                        else:
                            index, uint16_t = get_uint16_t(index, data)
                            index, attribute = get_string(index, uint16_t, data)
                            index, uint16_t = get_uint16_t(index, data)
                            index, value = get_string(index, uint16_t, data)
                        if attribute == b"":
                            groups[-1][1].append(check_bytes(value))
                        else:
                            groups.append((check_bytes(attribute), [check_bytes(value)]))
                        index, attr_type = get_uint8_t(index, data)

                        if attr_type in ATTRIBUTE_GROUP_TAGS:
                            break
                    except (KeyError, IndexError, struct.error) as error:
                        _q_s.logger.debug(
                            f"[{_q_s.NAME}]: Error while parsing attributes: {error}",
                            exc_info=True,
                        )
                        status = "failed"
                        break
                return groups, status

            @staticmethod
            def send_response(request: bytes, successful: bool) -> bytes:
                version, request_id = request[0:2], request[3:7]
                if version not in [b"\x01\x01", b"\x02\x00", b"\x02\x01", b"\x02\x02"]:
                    version = b"\x02\x00"
                status_code = STATUS_CODE_OK if successful else STATUS_CODE_BAD_REQUEST
                attributes = attributes_dict_to_bytes(
                    {"attributes-charset": "utf-8", "attributes-natural-language": "en-us"}
                )
                return version + status_code + request_id + attributes

        reactor.listenTCP(self.port, Site(MainResource()))
        reactor.run()

    def test_server(self, ip=None, port=None):
        from socket import socket, AF_INET, SOCK_STREAM

        _ip = ip or self.ip
        _port = port or self.port

        body = (
            b"\x02\x00\x00\x0b\x00\x01/p\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1b"
            b"attributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x00\x15"
            b"ipp://127.0.0.1:631/D\x00\x14requested-attributes\x00\x03allD\x00\x00\x00\x12"
            b"media-col-database\x03"
        )

        headers = (
            "POST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: {len(body)}\r\n"
            f"Host: {_ip}:{_port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        s = socket(AF_INET, SOCK_STREAM)
        s.connect((_ip, _port))
        s.sendall(headers.encode() + body)


def get_uint8_t(index, data):
    return index + 1, struct.unpack("b", data[index : index + 1])[0]


def get_uint16_t(index, data):
    return index + 2, struct.unpack(">H", data[index : index + 2])[0]


def get_uint32_t(index, data):
    return index + 4, struct.unpack(">I", data[index : index + 4])[0]


def get_string(index, length, data):
    return index + length, data[index : index + length]


def attributes_dict_to_bytes(attributes: dict[str, str]) -> bytes:
    attributes_str = b"\x01"  # start operation attributes
    for key, value in attributes.items():
        value_tag = ATTRIBUTE_NAME_TO_VALUE_TAG[key]
        name_length = len(key).to_bytes(2, "big")
        value_length = len(value).to_bytes(2, "big")
        attributes_str += value_tag + name_length + key.encode() + value_length + value.encode()
    attributes_str += b"\x03"  # end operation attributes
    return attributes_str


if __name__ == "__main__":
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qippserver = QIPPServer(
            ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config
        )
        qippserver.run_server()
