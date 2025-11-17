from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
import base64
import re

class imap_TCP:
    def __init__(self) -> None:
        self.view = ctx.master.addons.get("view")

    def tcp_message(self,flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message

        if not msg.from_client and (flow.server_conn.peername[1] == 993 or flow.server_conn.peername[1] == 143):
            server_msg = bytearray(msg.content)
            # ctx.log.warn(server_msg)
            if msg.content[0] == 0x17 and msg.content[1] == 0x03:
                server_msg[0:] = b'A NOOP\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)

addons = [imap_TCP()]