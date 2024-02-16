"""
//  -------------------------------------------------------------
//  author        jstucke
//  project       qeeqbox/honeypots
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
"""
from __future__ import annotations

from collections import defaultdict

from hl7apy.core import Message
from hl7apy.mllp import (
    AbstractErrorHandler,
    AbstractHandler,
    MLLPRequestHandler,
    MLLPServer,
    UnsupportedMessageType,
)
from hl7apy.parser import parse_message

from honeypots.base_server import BaseServer
from honeypots.helper import check_bytes, run_single_server


class HL7Server(BaseServer):
    NAME = "hl7_server"
    DEFAULT_PORT = 2575

    def server_main(self):
        _q_s = self

        class CustomMLLPRequestHandler(MLLPRequestHandler):
            def _route_message(self, msg):
                src_ip, src_port = self.client_address
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "data": {
                            "message": check_bytes(msg),
                        },
                    }
                )
                super()._route_message(msg)

        class CustomPDQHandler(AbstractHandler):
            def reply(self):
                _ = parse_message(self.incoming_message)
                # do something with the message

                res = Message("RSP_K21")
                # populate the message
                return res.to_mllp()

        class ErrorHandler(AbstractErrorHandler):
            def reply(self):
                if isinstance(self.exc, UnsupportedMessageType):
                    _q_s.logger.error(f"Error: {self.exc}")
                    _q_s.log(
                        {
                            "action": "error",
                            "data": {"exception": str(self.exc)},
                        }
                    )

        # hack for the handler to receive all messages regardless of the message type
        handlers: dict[str, tuple] = defaultdict(lambda: (CustomPDQHandler,))
        handlers["ERR"] = (ErrorHandler,)
        server = MLLPServer(
            self.ip, self.port, handlers, request_handler_class=CustomMLLPRequestHandler
        )
        server.serve_forever()

    def test_server(self, ip=None, port=None):
        pass


if __name__ == "__main__":
    run_single_server(HL7Server)
