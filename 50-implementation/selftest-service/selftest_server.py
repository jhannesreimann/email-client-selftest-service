#!/usr/bin/env python3

import argparse
import json
import os
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
import base64
import re


@dataclass(frozen=True)
class ModeDecision:
    mode: str
    source: str
    session: Optional[str] = None


_SESSION_RE = re.compile(r"^test-([A-Za-z0-9]{6,64})$")


def _extract_session_from_username(username: str) -> Optional[str]:
    u = username.strip()
    if "@" in u:
        u = u.split("@", 1)[0]
    m = _SESSION_RE.match(u)
    if not m:
        return None
    return m.group(1)


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s


def _b64decode_to_text(b64: bytes) -> Optional[str]:
    try:
        return base64.b64decode(b64, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return None


def _smtp_username_from_auth_plain(initial_response_b64: bytes) -> Optional[str]:
    decoded = _b64decode_to_text(initial_response_b64)
    if decoded is None:
        return None
    # RFC 4616: [authzid] \x00 authcid \x00 passwd
    parts = decoded.split("\x00")
    if len(parts) >= 3:
        return parts[1]
    if len(parts) == 2:
        return parts[0]
    return None


def _load_mode_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"default_mode": "baseline", "overrides": []}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_mode_store(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _decide_mode(mode_store_path: Path, client_ip: str) -> ModeDecision:
    data = _load_mode_store(mode_store_path)
    now = int(time.time())

    overrides: list[dict[str, Any]] = []
    chosen: Optional[ModeDecision] = None

    for o in data.get("overrides", []):
        exp = int(o.get("expires", 0))
        if exp and exp < now:
            continue
        overrides.append(o)
        if o.get("ip") == client_ip and chosen is None:
            sess = o.get("session")
            chosen = ModeDecision(mode=str(o.get("mode", "baseline")), source=f"override:{client_ip}", session=(str(sess) if sess is not None else None))

    if overrides != data.get("overrides", []):
        data["overrides"] = overrides
        _save_mode_store(mode_store_path, data)

    if chosen is not None:
        return chosen

    return ModeDecision(mode=str(data.get("default_mode", "baseline")), source="default", session=None)


def _should_block_implicit_tls(mode: str, server_port: int) -> bool:
    if mode not in {"t1", "t2", "t3", "t4"}:
        return False
    return server_port in {465, 993}


def _log_event(log_path: Optional[Path], event: dict[str, Any]) -> None:
    line = json.dumps(event, separators=(",", ":"))
    if log_path is None:
        print(line, flush=True)
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


class _LineIO:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_line(self, timeout: int = 120) -> Optional[bytes]:
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.rstrip(b"\r")


class SelfTestSMTPHandler(socketserver.BaseRequestHandler):
    server: "SelfTestSMTPServer"  # type: ignore[assignment]

    def handle(self) -> None:
        sock: socket.socket = self.request
        client_ip = self.client_address[0]
        dec = _decide_mode(self.server.mode_store_path, client_ip)

        tls_active = isinstance(sock, ssl.SSLSocket)
        server_port = int(self.server.server_address[1])

        if tls_active and _should_block_implicit_tls(dec.mode, server_port):
            _log_event(
                self.server.log_path,
                {
                    "ts": int(time.time()),
                    "proto": "smtp",
                    "client_ip": client_ip,
                    "mode": dec.mode,
                    "mode_source": dec.source,
                    "override_session": dec.session,
                    "session": None,
                    "tls": tls_active,
                    "server_port": server_port,
                    "event": "disconnect",
                    "reason": "implicit_tls_blocked",
                },
            )
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return

        _log_event(
            self.server.log_path,
            {
                "ts": int(time.time()),
                "proto": "smtp",
                "client_ip": client_ip,
                "mode": dec.mode,
                "mode_source": dec.source,
                "override_session": dec.session,
                "session": None,
                "tls": tls_active,
                "server_port": server_port,
                "event": "connect",
            },
        )

        io = _LineIO(sock)
        io.send(b"220 selftest ESMTP\r\n")

        pending_auth_login = False
        pending_auth_login_username: Optional[str] = None

        in_data = False
        data_bytes = 0
        mail_from_set = False
        rcpt_count = 0

        while True:
            line = io.recv_line()
            if line is None:
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "smtp",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "disconnect",
                    },
                )
                return
            u = line.upper()

            if in_data:
                # DATA mode ends with a single dot on its own line.
                if line == b".":
                    in_data = False
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "tls": tls_active,
                            "event": "data_end",
                            "bytes": data_bytes,
                        },
                    )
                    data_bytes = 0
                    io.send(b"250 2.0.0 OK\r\n")
                    continue

                # Do not log message contents.
                data_bytes += len(line) + 2
                continue

            if pending_auth_login:
                # AUTH LOGIN continuation (base64 username/password). We do not log/store the password.
                txt = _b64decode_to_text(line.strip())
                if pending_auth_login_username is None:
                    pending_auth_login_username = txt or ""
                    io.send(b"334 UGFzc3dvcmQ6\r\n")
                    continue

                username = pending_auth_login_username
                username_session = _extract_session_from_username(username) if username else None
                session = username_session
                if dec.session and username_session and dec.session != username_session:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "session_mismatch",
                            "override_session": dec.session,
                            "session": None,
                            "username": username,
                            "username_session": username_session,
                        },
                    )
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "smtp",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "auth_login",
                        "username": username,
                        "session": session,
                        "username_session": username_session,
                    },
                )
                io.send(b"235 2.7.0 Authentication successful\r\n")
                if dec.mode in {"t4"} and tls_active:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "drop",
                            "reason": "after_auth",
                        },
                    )
                    return
                pending_auth_login = False
                pending_auth_login_username = None
                continue

            if u.startswith(b"QUIT"):
                io.send(b"221 2.0.0 Bye\r\n")
                return

            if u.startswith(b"RSET"):
                mail_from_set = False
                rcpt_count = 0
                in_data = False
                data_bytes = 0
                io.send(b"250 2.0.0 OK\r\n")
                continue

            if u.startswith(b"NOOP"):
                io.send(b"250 2.0.0 OK\r\n")
                continue

            if u.startswith(b"EHLO") or u.startswith(b"HELO"):
                starttls_advertised = (not tls_active) and (dec.mode not in {"t1"})
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "smtp",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "ehlo",
                        "starttls_advertised": starttls_advertised,
                    },
                )

                caps: list[bytes] = [b"250-selftest", b"250-PIPELINING", b"250-SIZE 35882577", b"250-AUTH PLAIN LOGIN"]
                if starttls_advertised:
                    caps.append(b"250-STARTTLS")
                caps.append(b"250 HELP")
                io.send(b"\r\n".join(caps) + b"\r\n")
                continue

            if u.startswith(b"STARTTLS"):
                if tls_active:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "already_tls",
                        },
                    )
                    io.send(b"454 TLS not available due to temporary reason\r\n")
                    continue
                if dec.mode in {"t3"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "refused",
                        },
                    )
                    io.send(b"454 TLS not available due to temporary reason\r\n")
                    continue

                io.send(b"220 2.0.0 Ready to start TLS\r\n")
                if dec.mode in {"t2"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "drop_after_ready",
                        },
                    )
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disconnect",
                        },
                    )
                    return

                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "smtp",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "starttls",
                        "result": "ok",
                    },
                )

                try:
                    tls_sock = self.server.ssl_context.wrap_socket(sock, server_side=True)
                except Exception:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "wrap_failed",
                        },
                    )
                    return
                sock = tls_sock
                io = _LineIO(sock)
                tls_active = True
                if dec.mode in {"t4"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disrupt",
                            "reason": "after_handshake",
                            "payload": "NOOP",
                        },
                    )
                    try:
                        io.send(b"NOOP\r\n")
                    except Exception:
                        pass
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disconnect",
                        },
                    )
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return
                continue

            if u.startswith(b"MAIL FROM:"):
                mail_from_set = True
                rcpt_count = 0
                io.send(b"250 2.1.0 OK\r\n")
                continue

            if u.startswith(b"RCPT TO:"):
                if not mail_from_set:
                    io.send(b"503 5.5.1 Bad sequence of commands\r\n")
                    continue
                rcpt_count += 1
                io.send(b"250 2.1.5 OK\r\n")
                continue

            if u.startswith(b"DATA"):
                if not mail_from_set or rcpt_count <= 0:
                    io.send(b"503 5.5.1 Bad sequence of commands\r\n")
                    continue
                in_data = True
                data_bytes = 0
                io.send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                continue

            if u.startswith(b"AUTH"):
                # Handle common mechanisms enough to learn the username/session.
                # Never log raw payloads (they can contain credentials).
                parts = line.split()
                mech = parts[1].decode("utf-8", errors="replace") if len(parts) >= 2 else ""
                mech_u = mech.upper()
                username: Optional[str] = None

                if mech_u == "PLAIN":
                    if len(parts) >= 3:
                        username = _smtp_username_from_auth_plain(parts[2])
                    else:
                        io.send(b"334 \r\n")
                        resp = io.recv_line()
                        if resp is None:
                            return
                        username = _smtp_username_from_auth_plain(resp.strip())
                elif mech_u == "LOGIN":
                    pending_auth_login = True
                    pending_auth_login_username = None
                    io.send(b"334 VXNlcm5hbWU6\r\n")
                    continue

                username_session = _extract_session_from_username(username) if username else None
                session = username_session
                if dec.session and username_session and dec.session != username_session:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "smtp",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "session_mismatch",
                            "override_session": dec.session,
                            "session": None,
                            "username": username,
                            "username_session": username_session,
                        },
                    )
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "smtp",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "auth_command",
                        "auth_mech": mech_u or None,
                        "username": username,
                        "session": session,
                        "username_session": username_session,
                    },
                )
                io.send(b"235 2.7.0 Authentication successful\r\n")
                continue

            io.send(b"250 OK\r\n")


class SelfTestIMAPHandler(socketserver.BaseRequestHandler):
    server: "SelfTestIMAPServer"  # type: ignore[assignment]

    def handle(self) -> None:
        sock: socket.socket = self.request
        client_ip = self.client_address[0]
        dec = _decide_mode(self.server.mode_store_path, client_ip)

        tls_active = isinstance(sock, ssl.SSLSocket)
        server_port = int(self.server.server_address[1])

        if tls_active and _should_block_implicit_tls(dec.mode, server_port):
            _log_event(
                self.server.log_path,
                {
                    "ts": int(time.time()),
                    "proto": "imap",
                    "client_ip": client_ip,
                    "mode": dec.mode,
                    "mode_source": dec.source,
                    "override_session": dec.session,
                    "session": None,
                    "tls": tls_active,
                    "server_port": server_port,
                    "event": "disconnect",
                    "reason": "implicit_tls_blocked",
                },
            )
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return

        _log_event(
            self.server.log_path,
            {
                "ts": int(time.time()),
                "proto": "imap",
                "client_ip": client_ip,
                "mode": dec.mode,
                "mode_source": dec.source,
                "override_session": dec.session,
                "session": None,
                "tls": tls_active,
                "server_port": server_port,
                "event": "connect",
            },
        )

        io = _LineIO(sock)
        io.send(b"* OK selftest IMAP4rev1 Service Ready\r\n")

        while True:
            line = io.recv_line()
            if line is None:
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "imap",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "disconnect",
                    },
                )
                return

            parts = line.split(maxsplit=1)
            if not parts:
                continue
            tag = parts[0]
            cmd = parts[1] if len(parts) > 1 else b""
            ucmd = cmd.upper()

            if ucmd.startswith(b"LOGOUT"):
                io.send(b"* BYE Logging out\r\n")
                io.send(tag + b" OK LOGOUT completed\r\n")
                return

            if ucmd.startswith(b"CAPABILITY"):
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "imap",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "event": "capability",
                        "server_port": server_port,
                        "starttls_advertised": (not tls_active) and (dec.mode not in {"t1"}),
                    },
                )
                caps = [b"IMAP4rev1", b"AUTH=PLAIN", b"AUTH=LOGIN"]
                if (not tls_active) and (dec.mode not in {"t1"}):
                    caps.append(b"STARTTLS")
                io.send(b"* CAPABILITY " + b" ".join(caps) + b"\r\n")
                io.send(tag + b" OK CAPABILITY completed\r\n")
                continue

            if ucmd.startswith(b"STARTTLS"):
                if tls_active:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "already_tls",
                        },
                    )
                    io.send(tag + b" BAD STARTTLS not available\r\n")
                    continue
                if dec.mode in {"t1"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "refused",
                        },
                    )
                    io.send(tag + b" BAD STARTTLS not available\r\n")
                    continue
                if dec.mode in {"t3"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "refused",
                        },
                    )
                    io.send(tag + b" BAD STARTTLS not available\r\n")
                    continue

                io.send(tag + b" OK Begin TLS negotiation now\r\n")
                if dec.mode in {"t2"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "starttls",
                            "result": "drop_after_ok",
                        },
                    )
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disconnect",
                        },
                    )
                    return

                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "imap",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "override_session": dec.session,
                        "session": None,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "starttls",
                        "result": "ok",
                    },
                )

                try:
                    tls_sock = self.server.ssl_context.wrap_socket(sock, server_side=True)
                except Exception:
                    return
                sock = tls_sock
                io = _LineIO(sock)
                tls_active = True
                if dec.mode in {"t4"}:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disrupt",
                            "reason": "after_handshake",
                            "payload": "NOOP",
                        },
                    )
                    try:
                        io.send(b"NOOP\r\n")
                    except Exception:
                        pass
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "override_session": dec.session,
                            "session": None,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "disconnect",
                        },
                    )
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return
                continue

            if ucmd.startswith(b"NOOP") or ucmd.startswith(b"CHECK") or ucmd.startswith(b"STATUS") or ucmd.startswith(b"SELECT") or ucmd.startswith(b"EXAMINE"):
                cmd_name = ucmd.split(maxsplit=1)[0].decode("utf-8", errors="replace")
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "imap",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "command",
                        "cmd": cmd_name,
                    },
                )
                io.send(tag + b" OK\r\n")
                continue

            if ucmd.startswith(b"LOGIN"):
                # LOGIN typically carries username+password in cleartext on the wire.
                # Do not log the password; only log username/session + whether TLS was active.
                username: Optional[str] = None
                try:
                    # cmd starts with "LOGIN ..." (bytes)
                    rest = cmd.split(maxsplit=1)[1] if len(cmd.split(maxsplit=1)) > 1 else b""
                    fields = rest.split(maxsplit=1)
                    if fields:
                        username = _strip_quotes(fields[0].decode("utf-8", errors="replace"))
                except Exception:
                    username = None
                username_session = _extract_session_from_username(username) if username else None
                session = username_session
                if dec.session and username_session and dec.session != username_session:
                    _log_event(
                        self.server.log_path,
                        {
                            "ts": int(time.time()),
                            "proto": "imap",
                            "client_ip": client_ip,
                            "mode": dec.mode,
                            "mode_source": dec.source,
                            "tls": tls_active,
                            "server_port": server_port,
                            "event": "session_mismatch",
                            "override_session": dec.session,
                            "session": None,
                            "username": username,
                            "username_session": username_session,
                        },
                    )
                _log_event(
                    self.server.log_path,
                    {
                        "ts": int(time.time()),
                        "proto": "imap",
                        "client_ip": client_ip,
                        "mode": dec.mode,
                        "mode_source": dec.source,
                        "tls": tls_active,
                        "server_port": server_port,
                        "event": "login_command",
                        "username": username,
                        "session": session,
                        "username_session": username_session,
                    },
                )
                io.send(tag + b" OK Logged in\r\n")
                continue

            io.send(tag + b" OK\r\n")


class SelfTestSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[socketserver.BaseRequestHandler],
        ssl_context: ssl.SSLContext,
        implicit_tls: bool,
        mode_store_path: Path,
        log_path: Optional[Path],
    ) -> None:
        super().__init__(server_address, handler_class)
        self.ssl_context = ssl_context
        self.implicit_tls = implicit_tls
        self.mode_store_path = mode_store_path
        self.log_path = log_path

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        sock, addr = super().get_request()
        if self.implicit_tls:
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                raise
        return sock, addr


class SelfTestIMAPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[socketserver.BaseRequestHandler],
        ssl_context: ssl.SSLContext,
        implicit_tls: bool,
        mode_store_path: Path,
        log_path: Optional[Path],
    ) -> None:
        super().__init__(server_address, handler_class)
        self.ssl_context = ssl_context
        self.implicit_tls = implicit_tls
        self.mode_store_path = mode_store_path
        self.log_path = log_path

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        sock, addr = super().get_request()
        if self.implicit_tls:
            try:
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                raise
        return sock, addr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--smtp-port", type=int, default=587)
    ap.add_argument("--imap-port", type=int, default=143)
    ap.add_argument("--smtp-ports", default="25,465,587")
    ap.add_argument("--imap-ports", default="143,993")
    ap.add_argument("--mode-store", default="/var/lib/nsip-selftest/mode.json")
    ap.add_argument("--log", default="/var/log/nsip-selftest/events.jsonl")
    ap.add_argument("--tls-cert", required=True)
    ap.add_argument("--tls-key", required=True)
    args = ap.parse_args()

    mode_store_path = Path(args.mode_store)
    log_path = Path(args.log) if args.log else None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)

    smtp_ports = [int(p.strip()) for p in args.smtp_ports.split(",") if p.strip()] if args.smtp_ports.strip() else [int(args.smtp_port)]
    imap_ports = [int(p.strip()) for p in args.imap_ports.split(",") if p.strip()] if args.imap_ports.strip() else [int(args.imap_port)]

    smtps_implicit = {465}
    imaps_implicit = {993}

    servers: list[socketserver.ThreadingTCPServer] = []
    threads: list[threading.Thread] = []

    for p in smtp_ports:
        srv = SelfTestSMTPServer(
            (args.listen_host, p),
            SelfTestSMTPHandler,
            ctx,
            implicit_tls=(p in smtps_implicit),
            mode_store_path=mode_store_path,
            log_path=log_path,
        )
        servers.append(srv)
        threads.append(threading.Thread(target=srv.serve_forever, daemon=True))

    for p in imap_ports:
        srv = SelfTestIMAPServer(
            (args.listen_host, p),
            SelfTestIMAPHandler,
            ctx,
            implicit_tls=(p in imaps_implicit),
            mode_store_path=mode_store_path,
            log_path=log_path,
        )
        servers.append(srv)
        threads.append(threading.Thread(target=srv.serve_forever, daemon=True))

    for th in threads:
        th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
