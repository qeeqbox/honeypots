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
from contextlib import suppress
from random import randint

from hl7apy.core import Message, Field
from hl7apy.mllp import (
    AbstractErrorHandler,
    AbstractHandler,
    MLLPRequestHandler,
    MLLPServer,
    UnsupportedMessageType,
)
from hl7apy.parser import parse_message, parse_segment

from honeypots.base_server import BaseServer
from honeypots.helper import run_single_server


class HL7Server(BaseServer):
    NAME = "hl7_server"
    DEFAULT_PORT = 2575

    def server_main(self):  # noqa: C901
        _q_s = self

        class CustomMLLPRequestHandler(MLLPRequestHandler):
            def _route_message(self, msg):
                src_ip, src_port = self.client_address
                _q_s.log(
                    {
                        "action": "connection",
                        "src_ip": src_ip,
                        "src_port": src_port,
                    }
                )
                return super()._route_message(msg)

            def handle(self):
                with suppress(ConnectionResetError):
                    # we don't care about connection reset errors here
                    super().handle()

        class CustomPDQHandler(AbstractHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                try:
                    self.message = parse_message(self.incoming_message)
                    self.version = self._get_optional_field("msh_12") or "2.5"
                except Exception:
                    self.message = None
                    self.version = None
                self.response = Message("ACK", version=self.version) if self.version else None

            def reply(self):
                if not self.message:
                    return ""
                try:
                    _q_s.log(
                        {
                            "action": "query",
                            "data": {"message": self._parse_message()},
                        }
                    )
                    self._populate_header()
                    control_id = self._get_optional_field("msh_10")
                    ack_segment = parse_segment(f"MSA|AA|{control_id}", version=self.version)
                    self.response.add(ack_segment)
                except Exception as error:
                    _q_s.logger.debug(f"[{_q_s.NAME}] Error during response generation: {error}")
                return self.response.to_mllp()

            def _populate_header(self):
                sending_app = self._get_optional_field("msh_3")
                sending_facility = self._get_optional_field("msh_4")
                receiving_app = self._get_optional_field("msh_5")
                receiving_facility = self._get_optional_field("msh_6")
                processing_id = self._get_optional_field("msh_11")
                self._add_field_to_header("MSH_3", receiving_app)
                self._add_field_to_header("MSH_4", receiving_facility)
                self._add_field_to_header("MSH_5", sending_app)
                self._add_field_to_header("MSH_6", sending_facility)
                self._add_field_to_header("MSH_9", "ACK")
                self._add_field_to_header("MSH_10", str(randint(1000, 9000)))
                self._add_field_to_header("MSH_11", processing_id)

            def _add_field_to_header(self, field: str, value: str):
                if value is None:
                    return
                message_type = Field(field, version=self.version)
                message_type.value = value
                self.response.msh.add(message_type)

            def _get_optional_field(self, field: str) -> str | None:
                try:
                    return getattr(self.message.msh, field).value
                except AttributeError:
                    return None

            def _parse_message(self):
                return [
                    {
                        "name": segment.name,
                        "raw": segment.to_er7(),
                        "fields": [
                            {
                                "name": field.name,
                                "type": field.datatype,
                                "value": field.value,
                            }
                            for field in segment.children
                        ],
                    }
                    for segment in self.message.children
                ]

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


if __name__ == "__main__":
    run_single_server(HL7Server)
