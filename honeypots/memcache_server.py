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

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from random import randint, uniform
from time import time
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress


class QMemcacheServer():
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
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 11211
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def memcache_server_main(self):
        _q_s = self

        class CustomRedisProtocol(Protocol):

            _state = None

            def get_stats(self):
                items = randint(80000000, 90000000)
                ret = ''
                temp = {b'pid': randint(5, 400), b'uptime': randint(1000, 2000), b'time': int(time()), b'version': b'1.5.6', b'libevent': b'2.1.8-stable', b'pointer_size': 64, b'rusage_user': round(uniform(0.1, 0.9), 4), b'rusage_system': round(uniform(0.1, 0.9), 6), b'max_connections': 1024, b'curr_connections': randint(1, 1024), b'total_connections': 5, b'rejected_connections': 0, b'connection_structures': 2, b'reserved_fds': 20, b'cmd_get': 0, b'cmd_set': 40, b'cmd_flush': 0, b'cmd_touch': 0, b'get_hits': 0, b'get_misses': 0, b'get_expired': 0, b'get_flushed': 0, b'delete_misses': 0, b'delete_hits': 0, b'incr_misses': 0, b'incr_hits': 0, b'decr_misses': 0, b'decr_hits': 0, b'cas_misses': 0, b'cas_hits': 0, b'cas_badval': 0, b'touch_hits': 0, b'touch_misses': 0, b'auth_cmds': 0, b'auth_errors': 0, b'bytes_read': randint(7000000, 8000000), b'bytes_written': randint(500000, 1000000), b'limit_maxbytes': 33554432, b'accepting_conns': 1, b'listen_disabled_num': 0, b'time_in_listen_disabled_us': 0, b'threads': randint(4, 9000), b'conn_yields': 0, b'hash_power_level': 16, b'hash_bytes': 524288, b'hash_is_expanding': False, b'slab_reassign_rescues': 0, b'slab_reassign_chunk_rescues': 0, b'slab_reassign_evictions_nomem': 0, b'slab_reassign_inline_reclaim': 0, b'slab_reassign_busy_items': 0, b'slab_reassign_busy_deletes': 0, b'slab_reassign_running': False, b'slabs_moved': 0, b'lru_crawler_running': 0, b'lru_crawler_starts': randint(500000, 700000), b'lru_maintainer_juggles': randint(400000, 500000), b'malloc_fails': 0, b'log_worker_dropped': 0, b'log_worker_written': 0, b'log_watcher_skipped': 0, b'log_watcher_sent': 0, b'bytes': randint(13554432, 33554432), b'curr_items': items, b'total_items': items, b'slab_global_page_pool': 0, b'expired_unfetched': 0, b'evicted_unfetched': 0, b'evicted_active': 0, b'evictions': 0, b'reclaimed': 0, b'crawler_reclaimed': 0, b'crawler_items_checked': randint(5000, 6000), b'lrutail_reflocked': 0, b'moves_to_cold': randint(5000, 6000), b'moves_to_warm': randint(5000, 6000), b'moves_within_lru': 0, b'direct_reclaims': 0, b'lru_bumps_dropped': 0}

                for key, value in temp.items():
                    key = key.decode()
                    if isinstance(value, bytes):
                        value = value.decode()
                    ret += 'STAT {} {}\r\n'.format(key, value)

                ret = ret.encode() + b'END\r\n'
                return ret

            def get_key(self, key):
                ret = b''
                with suppress(Exception):
                    random = randint(80000000, 90000000)
                    temp = 'VALUE {} 0 {}\r\n{}\r\nEND\r\n'.format(key.decode(), len(str(random)), random)
                    ret = temp.encode()
                return ret

            def connectionMade(self):
                _q_s.logs.info({'server': 'memcache_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

            def dataReceived(self, data):
                with suppress(Exception):
                    _data = data.split(b'\r\n')[0].split(b' ')
                    if _data[0] == b'stats':
                        self.transport.write(self.get_stats())
                    elif _data[0] == b'get':
                        self.transport.write(self.get_key(_data[1]))
                    elif _data[0] == b'set':
                        name = _data[1]
                        size = _data[4]
                        value = data.split(b'\r\n')[1]
                        self.transport.write(b'STORED\r\n')
                    else:
                        self.transport.write(b'ERROR\r\n')
                    if _data[0] != b'':
                        _q_s.logs.info({'server': 'memcache_server', 'action': _data[0].decode(), 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                self.transport.loseConnection()

        factory = Factory()
        factory.protocol = CustomRedisProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
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

            self.logs.info({'server': 'memcache_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.memcache_server_main()

    def close_port(self):
        ret = close_port_wrapper('memcache_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('memcache_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from warnings import filterwarnings
            filterwarnings(action='ignore', module='.*socket.*')
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.connect((_ip, _port))
            c.send(b'stats\r\n')
            data, address = c.recvfrom(10000)
            c.close()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        QMemcacheServer = QMemcacheServer(ip=parsed.ip, port=parsed.port, options=parsed.options, config=parsed.config)
        QMemcacheServer.run_server()
