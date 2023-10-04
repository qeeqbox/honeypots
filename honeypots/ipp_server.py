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

from typing import Dict
from requests.packages.urllib3 import disable_warnings
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress
from struct import unpack

disable_warnings()

STATUS_CODE_OK = b"\x00\x00"
STATUS_CODE_BAD_REQUEST = b"\x04\x00"


class QIPPServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 631
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def ipp_server_main(self):
        _q_s = self

        class MainResource(Resource):
            isLeaf = True
            operations_supported = {0x0001: 'Reserved', 0x0002: 'Print-Job', 0x0003: 'Print-URI', 0x0004: 'Validate-Job', 0x0005: 'Create-Job', 0x0006: 'Send-Document', 0x0007: 'Send-URI', 0x0008: 'Cancel-Job', 0x0009: 'Get-Job-Attributes', 0x000A: 'Get-Jobs', 0x000B: 'Get-Printer-Attributes', 0x000C: 'Hold-Job', 0x000D: 'Release-Job', 0x000E: 'Restart-Job', 0x000F: 'Reserved', 0x0010: 'Pause-Printer', 0x0011: 'Resume-Printer', 0x0012: 'Purge-Jobs', 0x0013: 'Set-Printer-Attributes', 0x0014: 'Set-Job-Attributes', 0x0015: 'Get-Printer-Supported-Values', 0x0016: 'Create-Printer-Subscriptions', 0x0017: 'Create-Job-Subscriptions', 0x0018: 'Get-Subscription-Attributes', 0x0019: 'Get-Subscriptions', 0x001A: 'Renew-Subscription', 0x001B: 'Cancel-Subscription', 0x001C: 'Get-Notifications', 0x001D: 'ipp-indp-method', 0x001E: 'Get-Resource-Attributes', 0x001F: 'ipp-get-resources', 0x0020: 'Get-Resources', 0x0021: 'ipp-install', 0x0022: 'Enable-Printer', 0x0023: 'Disable-Printer', 0x0024: 'Pause-Printer-After-Current-Job', 0x0025: 'Hold-New-Jobs', 0x0026: 'Release-Held-New-Jobs', 0x0027: 'Deactivate-Printer', 0x0028: 'Activate-Printer', 0x0029: 'Restart-Printer', 0x002A: 'Shutdown-Printer', 0x002B: 'Startup-Printer', 0x002C: 'Reprocess-Job', 0x002D: 'Cancel-Current-Job', 0x002E: 'Suspend-Current-Job', 0x002F: 'Resume-Job', 0x0030: 'Promote-Job', 0x0031: 'Schedule-Job-After', 0x0033: 'Cancel-Document', 0x0034: 'Get-Document-Attributes', 0x0035: 'Get-Documents', 0x0036: 'Delete-Document', 0x0037: 'Set-Document-Attributes', 0x0038: 'Cancel-Jobs', 0x0039: 'Cancel-My-Jobs', 0x003A: 'Resubmit-Job', 0x003B: 'Close-Job', 0x003C: 'Identify-Printer', 0x003D: 'Validate-Document', 0x003E: 'Add-Document-Images', 0x003F: 'Acknowledge-Document', 0x0040: 'Acknowledge-Identify-Printer', 0x0041: 'Acknowledge-Job', 0x0042: 'Fetch-Document', 0x0043: 'Fetch-Job', 0x0044: 'Get-Output-Device-Attributes', 0x0045: 'Update-Active-Jobs', 0x0046: 'Deregister-Output-Device', 0x0047: 'Update-Document-Status', 0x0048: 'Update-Job-Status', 0x0049: 'Update-Output-Device-Attributes', 0x004A: 'Get-Next-Document-Data', 0x004B: 'Allocate-Printer-Resources', 0x004C: 'Create-Printer', 0x004D: 'Deallocate-Printer-Resources', 0x004E: 'Delete-Printer', 0x004F: 'Get-Printers', 0x0050: 'Shutdown-One-Printer', 0x0051: 'Startup-One-Printer', 0x0052: 'Cancel-Resource', 0x0053: 'Create-Resource', 0x0054: 'Install-Resource', 0x0055: 'Send-Resource-Data', 0x0056: 'Set-Resource-Attributes', 0x0057: 'Create-Resource-Subscriptions', 0x0058: 'Create-System-Subscriptions', 0x0059: 'Disable-All-Printers', 0x005A: 'Enable-All-Printers', 0x005B: 'Get-System-Attributes', 0x005C: 'Get-System-Supported-Values', 0x005D: 'Pause-All-Printers', 0x005E: 'Pause-All-Printers-After-Current-Job', 0x005F: 'Register-Output-Device', 0x0060: 'Restart-System', 0x0061: 'Resume-All-Printers', 0x0062: 'Set-System-Attributes', 0x0063: 'Shutdown-All-Printers', 0x0064: 'Startup-All-Printers', 0x0065: 'Get-Printer-Resources', 0x0066: 'Get-User-Printer-Attributes', 0x0067: 'Restart-One-Printer'}

            attribute_group_tags = {0x00: 'Reserved', 0x01: 'operation-attributes-tag', 0x02: 'job-attributes-tag', 0x03: 'end-of-attributes-tag', 0x04: 'printer-attributes-tag', 0x05: 'unsupported-attributes-tag', 0x06: 'subscription-attributes-tag', 0x07: 'event-notification-attributes-tag', 0x08: 'resource-attributes-tag', 0x09: 'document-attributes-tag', 0x0A: 'system-attributes-tag'}

            attribute_syntaxes = {0x20: 'Unassigned', 0x21: 'integer', 0x22: 'boolean', 0x23: 'enum', 0x30: 'octetString', 0x31: 'dateTime', 0x32: 'resolution', 0x33: 'rangeOfInteger', 0x34: 'begCollection', 0x35: 'textWithLanguage', 0x36: 'nameWithLanguage', 0x37: 'endCollection', 0x40: 'Unassigned', 0x41: 'textWithoutLanguage', 0x42: 'nameWithoutLanguage', 0x43: 'Unassigned', 0x44: 'keyword', 0x45: 'uri', 0x46: 'uriScheme', 0x47: 'charset', 0x48: 'naturalLanguage', 0x49: 'mimeMediaType', 0x4A: 'memberAttrName', 0x7F: 'extension'}

            status_codes = {0x0000: 'successful-ok', 0x0001: 'successful-ok-ignored-or-substituted-attributes', 0x0002: 'successful-ok-conflicting-attributes', 0x0003: 'successful-ok-ignored-subscriptions', 0x0004: 'ipp-indp-method', 0x0005: 'successful-ok-too-many-events', 0x0006: 'ipp-indp-method', 0x0007: 'successful-ok-events-complete', 0x0300: 'ipp-get-method', 0x0400: 'client-error-bad-request', 0x0401: 'client-error-forbidden', 0x0402: 'client-error-not-authenticated', 0x0403: 'client-error-not-authorized', 0x0404: 'client-error-not-possible', 0x0405: 'client-error-timeout', 0x0406: 'client-error-not-found', 0x0407: 'client-error-gone', 0x0408: 'client-error-request-entity-too-large', 0x0409: 'client-error-request-value-too-long', 0x040A: 'client-error-document-format-not-supported', 0x040B: 'client-error-attributes-or-values-not-supported', 0x040C: 'client-error-uri-scheme-not-supported', 0x040D: 'client-error-charset-not-supported', 0x040E: 'client-error-conflicting-attributes', 0x040F: 'client-error-compression-not-supported', 0x0410: 'client-error-compression-error', 0x0411: 'client-error-document-format-error', 0x0412: 'client-error-document-access-error', 0x0413: 'client-error-attributes-not-settable', 0x0414: 'client-error-ignored-all-subscriptions', 0x0415: 'client-error-too-many-subscriptions', 0x0416: 'ipp-indp-method', 0x0417: 'ipp-install', 0x0418: 'client-error-document-password-error', 0x0419: 'client-error-document-permission-error', 0x041A: 'client-error-document-security-error', 0x041B: 'client-error-document-unprintable-error', 0x041C: 'client-error-account-info-needed', 0x041D: 'client-error-account-closed', 0x041E: 'client-error-account-limit-reached', 0x041F: 'client-error-account-authorization-failed', 0x0420: 'client-error-not-fetchable', 0x0500: 'server-error-internal-error', 0x0501: 'server-error-operation-not-supported', 0x0502: 'server-error-service-unavailable', 0x0503: 'server-error-version-not-supported', 0x0504: 'server-error-device-error', 0x0505: 'server-error-temporary-error', 0x0506: 'server-error-not-accepting-jobs', 0x0507: 'server-error-busy', 0x0508: 'server-error-job-canceled', 0x0509: 'server-error-multiple-document-jobs-not-supported', 0x050A: 'server-error-printer-is-deactivated', 0x050B: 'server-error-too-many-jobs', 0x050C: 'server-error-too-many-documents'}

            def get_uint8_t(self, index, data):
                return index + 1, unpack('b', data[index:index + 1])[0]

            def get_uint16_t(self, index, data):
                return index + 2, unpack('>H', data[index:index + 2])[0]

            def get_uint32_t(self, index, data):
                return index + 4, unpack('>I', data[index:index + 4])[0]

            def get_string(self, index, length, data):
                return index + length, data[index:index + length]

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def render_POST(self, request):

                headers = {}
                client_ip = ""

                with suppress(Exception):
                    def check_bytes(string):
                        if isinstance(string, bytes):
                            return string.decode()
                        else:
                            return str(string)

                    for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                        headers.update({check_bytes(item): ','.join(map(check_bytes, value))})
                    headers.update({'method': check_bytes(request.method)})
                    headers.update({'uri': check_bytes(request.uri)})

                if 'fix_get_client_ip' in _q_s.options:
                    with suppress(Exception):
                        raw_headers = dict(request.requestHeaders.getAllRawHeaders())
                        if b'X-Forwarded-For' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Forwarded-For'][0])
                        elif b'X-Real-IP' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Real-IP'][0])

                if client_ip == "":
                    client_ip = request.getClientAddress().host

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'ipp_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})
                    else:
                        _q_s.logs.info({'server': 'ipp_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                data = request.content.read()

                response = ''
                version = [0, 0]
                request_id = 0
                group = ''
                groups = []
                groups_parsed = ''
                operation = ''
                status = 'success'

                with suppress(Exception):
                    index, version[0] = self.get_uint8_t(0, data)
                    index, version[1] = self.get_uint8_t(index, data)
                    index, uint16_t = self.get_uint16_t(index, data)
                    operation = self.operations_supported[uint16_t]
                    index, request_id = self.get_uint32_t(index, data)
                    index, uint8_t = self.get_uint8_t(index, data)
                    group = self.attribute_group_tags[uint8_t]
                    index, uint8_t = self.get_uint8_t(index, data)
                    to_parse_len = len(data[index:])
                    if uint8_t in self.attribute_syntaxes:
                        while index < to_parse_len:
                            try:
                                attribute = ''
                                value = ''
                                if self.attribute_syntaxes[uint8_t] == 'integer':
                                    index, attribute = self.get_uint32_t(index, data)
                                elif self.attribute_syntaxes[uint8_t] == 'boolean':
                                    index, attribute = self.get_uint8_t(index, data)
                                else:
                                    index, uint16_t = self.get_uint16_t(index, data)
                                    index, attribute = self.get_string(index, uint16_t, data)
                                    index, uint16_t = self.get_uint16_t(index, data)
                                    index, value = self.get_string(index, uint16_t, data)
                                if attribute == b'':
                                    groups[-1][1].append(self.check_bytes(value))
                                else:
                                    groups.append([self.check_bytes(attribute), [self.check_bytes(value)]])
                                index, uint8_t = self.get_uint8_t(index, data)

                                if uint8_t in self.attribute_group_tags:
                                    break
                            except BaseException:
                                status = 'failed'
                                break

                with suppress(Exception):
                    response += ''
                    response = 'VERSION {}.{}|'.format(version[0], version[1])
                    response += 'REQUEST {}|'.format(hex(request_id))
                    response += 'OPERATION {}|'.format(operation)
                    response += 'GROUP {}|'.format(group)
                    if len(groups) > 0:
                        for i in groups:
                            groups_parsed += 'ATTR ' + i[0] + ' ' + ','.join(i[1]) + '|'
                        groups_parsed = groups_parsed.strip()
                    response += groups_parsed
                with suppress(Exception):
                    if response[-1] == '|':
                        response = response[0:-1]
                if len(response) > 0:
                    _q_s.logs.info({'server': 'ipp_server', 'action': 'query', 'status': status, 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': {'request': response}})
                return self.send_response(data, status != "failed")

            @staticmethod
            def send_response(request: bytes, successful: bool) -> bytes:
                version, request_id = request[0:2], request[3:7]
                if version not in [b"\x01\x01", b"\x02\x00", b"\x02\x01", b"\x02\x02"]:
                    version = b"\x02\x00"
                status_code = STATUS_CODE_OK if successful else STATUS_CODE_BAD_REQUEST
                attributes = attributes_dict_to_bytes({"attributes-charset": "utf-8", "attributes-natural-language": "en-us"})
                response = version + status_code + request_id + attributes
                return response

        reactor.listenTCP(self.port, Site(MainResource()))
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

            self.logs.info({'server': 'ipp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ipp_server_main()

    def close_port(self):
        ret = close_port_wrapper('ipp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ipp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None):
        with suppress():
            from socket import socket, AF_INET, SOCK_STREAM
            _ip = ip or self.ip
            _port = port or self.port

            body = b'\x02\x00\x00\x0b\x00\x01/p\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x00\x15ipp://127.0.0.1:631/D\x00\x14requested-attributes\x00\x03allD\x00\x00\x00\x12media-col-database\x03'

            headers = """\
            POST / HTTP/1.1\r
            Content-Type: application/x-www-form-urlencoded\r
            Content-Length: {}\r
            Host: {}:{}\r
            Connection: close\r
            \r\n""".format(len(body), _ip, _port).encode()

            s = socket(AF_INET, SOCK_STREAM)
            s.connect((_ip, _port))
            s.sendall(headers + body)


ATTRIBUTE_NAME_TO_VALUE_TAG = {
    "attributes-charset": b"\x47",
    "attributes-natural-language": b"\x48",
}


def attributes_dict_to_bytes(attributes: Dict[str, str]) -> bytes:
    attributes_str = b"\x01"  # start operation attributes
    for key, value in attributes.items():
        value_tag = ATTRIBUTE_NAME_TO_VALUE_TAG[key]
        name_length = len(key).to_bytes(2, "big")
        value_length = len(value).to_bytes(2, "big")
        attributes_str += value_tag + name_length + key.encode() + value_length + value.encode()
    attributes_str += b"\x03"  # end operation attributes
    return attributes_str


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qippserver = QIPPServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        qippserver.run_server()
