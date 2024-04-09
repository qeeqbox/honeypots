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

from contextlib import suppress
from random import randint, uniform
from time import time

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

from honeypots.base_server import BaseServer
from honeypots.helper import (
    run_single_server,
)


class QMemcacheServer(BaseServer):
    NAME = "memcache_server"
    DEFAULT_PORT = 11211

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomRedisProtocol(Protocol):
            _state = None

            def get_stats(self) -> bytes:
                items = randint(80000000, 90000000)
                ret = ""
                temp = {
                    "pid": randint(5, 400),
                    "uptime": randint(1000, 2000),
                    "time": int(time()),
                    "version": "1.5.6",
                    "libevent": "2.1.8-stable",
                    "pointer_size": 64,
                    "rusage_user": round(uniform(0.1, 0.9), 4),
                    "rusage_system": round(uniform(0.1, 0.9), 6),
                    "max_connections": 1024,
                    "curr_connections": randint(1, 1024),
                    "total_connections": 5,
                    "rejected_connections": 0,
                    "connection_structures": 2,
                    "reserved_fds": 20,
                    "cmd_get": 0,
                    "cmd_set": 40,
                    "cmd_flush": 0,
                    "cmd_touch": 0,
                    "get_hits": 0,
                    "get_misses": 0,
                    "get_expired": 0,
                    "get_flushed": 0,
                    "delete_misses": 0,
                    "delete_hits": 0,
                    "incr_misses": 0,
                    "incr_hits": 0,
                    "decr_misses": 0,
                    "decr_hits": 0,
                    "cas_misses": 0,
                    "cas_hits": 0,
                    "cas_badval": 0,
                    "touch_hits": 0,
                    "touch_misses": 0,
                    "auth_cmds": 0,
                    "auth_errors": 0,
                    "bytes_read": randint(7000000, 8000000),
                    "bytes_written": randint(500000, 1000000),
                    "limit_maxbytes": 33554432,
                    "accepting_conns": 1,
                    "listen_disabled_num": 0,
                    "time_in_listen_disabled_us": 0,
                    "threads": randint(4, 9000),
                    "conn_yields": 0,
                    "hash_power_level": 16,
                    "hash_bytes": 524288,
                    "hash_is_expanding": False,
                    "slab_reassign_rescues": 0,
                    "slab_reassign_chunk_rescues": 0,
                    "slab_reassign_evictions_nomem": 0,
                    "slab_reassign_inline_reclaim": 0,
                    "slab_reassign_busy_items": 0,
                    "slab_reassign_busy_deletes": 0,
                    "slab_reassign_running": False,
                    "slabs_moved": 0,
                    "lru_crawler_running": 0,
                    "lru_crawler_starts": randint(500000, 700000),
                    "lru_maintainer_juggles": randint(400000, 500000),
                    "malloc_fails": 0,
                    "log_worker_dropped": 0,
                    "log_worker_written": 0,
                    "log_watcher_skipped": 0,
                    "log_watcher_sent": 0,
                    "bytes": randint(13554432, 33554432),
                    "curr_items": items,
                    "total_items": items,
                    "slab_global_page_pool": 0,
                    "expired_unfetched": 0,
                    "evicted_unfetched": 0,
                    "evicted_active": 0,
                    "evictions": 0,
                    "reclaimed": 0,
                    "crawler_reclaimed": 0,
                    "crawler_items_checked": randint(5000, 6000),
                    "lrutail_reflocked": 0,
                    "moves_to_cold": randint(5000, 6000),
                    "moves_to_warm": randint(5000, 6000),
                    "moves_within_lru": 0,
                    "direct_reclaims": 0,
                    "lru_bumps_dropped": 0,
                }

                for key, value in temp.items():
                    ret += f"STAT {key} {value}\r\n"
                ret += "END\r\n"
                return ret.encode()

            def get_key(self, key: bytes) -> bytes:
                try:
                    random = randint(80000000, 90000000)
                    temp = f"VALUE {key.decode()} 0 {len(str(random))}\r\n{random}\r\nEND\r\n"
                    return temp.encode()
                except UnicodeDecodeError:
                    return b""

            def connectionMade(self):  # noqa: N802
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": self.transport.getPeer().host,
                        "src_port": self.transport.getPeer().port,
                    }
                )

            def dataReceived(self, data: bytes):  # noqa: N802
                with suppress(Exception):
                    _data = data.split(b"\r\n")[0].split(b" ")
                    if _data[0] == b"stats":
                        self.transport.write(self.get_stats())
                    elif _data[0] == b"get":
                        self.transport.write(self.get_key(_data[1]))
                    elif _data[0] == b"set" and len(_data) > 4:  # noqa: PLR2004
                        self.transport.write(b"STORED\r\n")
                    else:
                        self.transport.write(b"ERROR\r\n")
                    if _data[0] != b"":
                        _q_s.log(
                            {
                                "action": _data[0].decode(),
                                "src_ip": self.transport.getPeer().host,
                                "src_port": self.transport.getPeer().port,
                            }
                        )
                self.transport.loseConnection()

        factory = Factory()
        factory.protocol = CustomRedisProtocol
        reactor.listenTCP(port=self.port, factory=factory, interface=self.ip)
        reactor.run()

    def test_server(self, ip=None, port=None, username=None, password=None):  # noqa: ARG002
        with suppress(Exception):
            from warnings import filterwarnings

            filterwarnings(action="ignore", module=".*socket.*")
            from socket import socket, AF_INET, SOCK_STREAM

            _ip = ip or self.ip
            _port = port or self.port
            c = socket(AF_INET, SOCK_STREAM)
            c.connect((_ip, _port))
            c.send(b"stats\r\n")
            c.recvfrom(10000)
            c.close()


if __name__ == "__main__":
    run_single_server(QMemcacheServer)
