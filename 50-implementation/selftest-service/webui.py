#!/usr/bin/env python3

import argparse
import json
import os
import secrets
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse


def _load_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"default_mode": "baseline", "overrides": []}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_store(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _prune_overrides(data: dict[str, Any]) -> None:
    now = int(time.time())
    overrides = []
    for o in data.get("overrides", []):
        exp = int(o.get("expires", 0))
        if exp and exp >= now:
            overrides.append(o)
    data["overrides"] = overrides


def _client_ip(req: Request) -> str:
    # We expect nginx to set X-Forwarded-For. If not present, fall back to direct client.
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",", 1)[0].strip()
    if req.client is None:
        return "unknown"
    return req.client.host


def _new_session_code() -> str:
    # URL-safe, alnum only in our username format. 8 chars feels ok for collisions.
    # We keep it in [A-Za-z0-9] by stripping '-' and '_'.
    raw = secrets.token_urlsafe(8)
    cleaned = "".join(ch for ch in raw if ch.isalnum())
    return (cleaned[:10] or "X")


def _html_page(title: str, body_html: str) -> str:
    return """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>__TITLE__</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    :root {
      color-scheme: dark;
      --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      --ocean-primary: #0f172a;
      --ocean-secondary: #1e293b;
      --ocean-accent: #0ea5e9;
      --glass-bg: rgba(255, 255, 255, 0.03);
      --glass-border: rgba(255, 255, 255, 0.08);
      --text-primary: #ffffff;
      --text-secondary: rgba(255, 255, 255, 0.7);
      --shadow-premium: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }

    html, body { height: 100%; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', Roboto, sans-serif;
      min-height: 100vh;
      background: radial-gradient(ellipse at bottom, var(--ocean-secondary) 0%, var(--ocean-primary) 100%);
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-primary);
      overflow: hidden;
      line-height: 1.5;
    }

    /* Dynamic Ocean Background */
    .ocean-container {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .depth-layer {
      position: absolute;
      width: 120%;
      height: 120%;
      border-radius: 50%;
      animation: float 20s ease-in-out infinite;
      opacity: 0.12;
      will-change: transform;
    }

    .depth-layer:nth-child(1) {
      background: radial-gradient(circle, #0ea5e9 0%, transparent 70%);
      top: 10%;
      left: -10%;
      animation-delay: 0s;
      animation-duration: 25s;
    }

    .depth-layer:nth-child(2) {
      background: radial-gradient(circle, #06b6d4 0%, transparent 70%);
      bottom: 10%;
      right: -10%;
      animation-delay: -8s;
      animation-duration: 30s;
    }

    .depth-layer:nth-child(3) {
      background: radial-gradient(circle, #8b5cf6 0%, transparent 70%);
      top: 50%;
      left: 30%;
      animation-delay: -15s;
      animation-duration: 35s;
    }

    @keyframes float {
      0%, 100% { transform: translate(0, 0) rotate(0deg) scale(1); }
      25% { transform: translate(-20px, -30px) rotate(1deg) scale(1.05); }
      50% { transform: translate(30px, 20px) rotate(-1deg) scale(0.95); }
      75% { transform: translate(-10px, 40px) rotate(0.5deg) scale(1.02); }
    }

    /* Particle System */
    .particle {
      position: absolute;
      width: 2px;
      height: 2px;
      background: #0ea5e9;
      border-radius: 50%;
      opacity: 0;
      animation: particle-float 15s linear infinite;
    }

    @keyframes particle-float {
      0% {
        opacity: 0;
        transform: translateY(100vh) translateX(0) scale(0);
      }
      10% { opacity: 1; }
      90% { opacity: 1; }
      100% {
        opacity: 0;
        transform: translateY(-100px) translateX(100px) scale(1);
      }
    }

    /* Premium Glass Container */
    .login-container {
      width: min(980px, calc(100vw - 28px));
      max-height: calc(100vh - 28px);
      padding: 38px 34px;
      background: var(--glass-bg);
      backdrop-filter: blur(40px) saturate(180%);
      border: 1px solid var(--glass-border);
      border-radius: 32px;
      box-shadow: var(--shadow-premium), inset 0 1px 0 rgba(255,255,255,0.05);
      z-index: 100;
      position: relative;
      overflow: auto;
      -webkit-overflow-scrolling: touch;
      animation: containerEntrance 1.2s cubic-bezier(0.4, 0, 0.2, 1) both;
    }

    @keyframes containerEntrance {
      0% {
        opacity: 0;
        transform: translateY(40px) scale(0.95);
        filter: blur(10px);
      }
      100% {
        opacity: 1;
        transform: translateY(0) scale(1);
        filter: blur(0);
      }
    }

    .login-container::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      border-radius: 32px;
      padding: 1px;
      background: linear-gradient(145deg, rgba(255,255,255,0.1), rgba(255,255,255,0.02));
      mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
      mask-composite: xor;
      -webkit-mask-composite: xor;
      pointer-events: none;
    }

    h1 {
      font-size: 34px;
      font-weight: 700;
      letter-spacing: -1px;
      margin-bottom: 10px;
      background: linear-gradient(135deg, #ffffff, #cbd5e1);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    h2 {
      font-size: 20px;
      font-weight: 650;
      letter-spacing: -0.3px;
      margin-top: 18px;
      margin-bottom: 10px;
      color: var(--text-primary);
    }

    .glass-panel {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 20px;
      padding: 16px 16px;
      box-shadow: 0 14px 36px rgba(0, 0, 0, 0.18);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      position: relative;
    }

    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    @media (max-width: 760px) {
      .grid-2 { grid-template-columns: 1fr; }
    }

    .pill {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(14, 165, 233, 0.12);
      color: rgba(255,255,255,0.95);
      font-weight: 650;
      letter-spacing: 0.2px;
    }

    .kv {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin: 10px 0;
    }

    .kv > div { min-width: 220px; }

    .row { margin: 12px 0; }
    .muted { color: var(--text-secondary); }

    code, pre {
      background: rgba(255, 255, 255, 0.04);
      border: 1.5px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      color: var(--text-primary);
    }

    code {
      padding: 3px 10px;
      display: inline-block;
      backdrop-filter: blur(10px);
    }

    pre {
      padding: 14px;
      overflow-x: auto;
      margin-top: 10px;
    }

    a { color: #7dd3fc; text-decoration: none; }
    a:hover { color: #38bdf8; }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 44px;
      padding: 0 16px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      cursor: pointer;
      text-decoration: none;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 8px 32px rgba(14, 165, 233, 0.12);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    .btn:hover {
      transform: translateY(-1px);
      border-color: rgba(14, 165, 233, 0.35);
      background: rgba(255, 255, 255, 0.06);
      box-shadow: 0 16px 48px rgba(14, 165, 233, 0.20);
    }

    .btn:active {
      transform: translateY(0);
      transition-duration: 0.1s;
    }

    select {
      background: rgba(255, 255, 255, 0.04) !important;
      border: 1.5px solid rgba(255, 255, 255, 0.08) !important;
      color: var(--text-primary) !important;
      border-radius: 14px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    table { border-collapse: collapse; width: 100%; overflow: hidden; border-radius: 14px; }
    th, td { border-bottom: 1px solid rgba(255,255,255,0.08); padding: 10px 10px; text-align: left; }
    th { color: var(--text-secondary); font-weight: 650; }

    /* Responsive Design */
    @media (max-width: 520px) {
      .login-container {
        padding: 26px 18px;
        border-radius: 26px;
      }
      h1 { font-size: 28px; }
      .btn { width: 100%; }
    }

    @media (max-height: 700px) {
      .login-container { padding: 26px 26px; }
    }

    /* Accessibility */
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <div class=\"ocean-container\" aria-hidden=\"true\">
    <div class=\"depth-layer\"></div>
    <div class=\"depth-layer\"></div>
    <div class=\"depth-layer\"></div>
  </div>
  <div class=\"login-container\">__BODY__</div>
  <script>
    (() => {
      const prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const ocean = document.querySelector('.ocean-container');
      if (!ocean) return;

      function createParticle() {
        if (prefersReduced) return;
        const particle = document.createElement('div');
        particle.className = 'particle';
        const size = Math.random() * 3 + 1;
        particle.style.width = size + 'px';
        particle.style.height = size + 'px';
        particle.style.left = Math.random() * window.innerWidth + 'px';
        particle.style.animationDelay = Math.random() * 2 + 's';
        particle.style.animationDuration = (Math.random() * 10 + 10) + 's';

        const colors = ['#0ea5e9', '#06b6d4', '#8b5cf6', '#06b6d4'];
        particle.style.background = colors[Math.floor(Math.random() * colors.length)];
        ocean.appendChild(particle);
        setTimeout(() => particle.remove(), 15000);
      }

      if (!prefersReduced) {
        setInterval(createParticle, 1500);
        window.addEventListener('load', () => {
          for (let i = 0; i < 8; i++) {
            setTimeout(createParticle, i * 200);
          }
        });
      }

      // Mouse movement parallax for depth layers
      if (!prefersReduced) {
        document.addEventListener('mousemove', (e) => {
          const layers = document.querySelectorAll('.depth-layer');
          const x = (e.clientX / window.innerWidth) * 100;
          const y = (e.clientY / window.innerHeight) * 100;
          layers.forEach((layer, index) => {
            const speed = (index + 1) * 0.5;
            layer.style.transform = `translate(${x * speed * 0.1}px, ${y * speed * 0.1}px)`;
          });
        }, { passive: true });
      }
    })();
  </script>
</body>
</html>""".replace("__TITLE__", title).replace("__BODY__", body_html)


def _mode_buttons() -> str:
    modes = ["baseline", "t1", "t2", "t3", "t4"]
    parts = []
    for m in modes:
        parts.append(f"<a class=\"btn\" href=\"/start?mode={m}\">Start {m.upper()}</a>")
    return " ".join(parts)


def _read_events(events_path: Path, limit_lines: int = 2000) -> list[dict[str, Any]]:
    if not events_path.exists():
        return []
    # Simple tail-read: read last N lines (good enough for MVP).
    with events_path.open("rb") as f:
        data = f.read()
    lines = data.splitlines()[-limit_lines:]
    out: list[dict[str, Any]] = []
    for ln in lines:
        try:
            out.append(json.loads(ln.decode("utf-8")))
        except Exception:
            continue
    return out


def _summarize_session(events: list[dict[str, Any]], session: str) -> dict[str, Any]:
    hits = [e for e in events if e.get("session") == session]
    hits = sorted(hits, key=lambda e: int(e.get("ts", 0)))

    auth_events = {"auth_command", "auth_login", "login_command"}
    connect_events = {"connect"}
    disconnect_events = {"disconnect"}

    def _proto_summary(proto: str) -> dict[str, Any]:
        proto_hits = [e for e in hits if e.get("proto") == proto]
        ports = sorted({int(e.get("server_port")) for e in proto_hits if isinstance(e.get("server_port"), int) or str(e.get("server_port", "")).isdigit()})
        connects = [e for e in proto_hits if e.get("event") in connect_events]
        disconnects = [e for e in proto_hits if e.get("event") in disconnect_events]
        auth_plain = [e for e in proto_hits if (e.get("event") in auth_events) and (e.get("tls") is False)]
        auth_tls = [e for e in proto_hits if (e.get("event") in auth_events) and (e.get("tls") is True)]
        starttls = [e for e in proto_hits if e.get("event") == "starttls"]
        starttls_results: dict[str, int] = {}
        for s in starttls:
            r = str(s.get("result") or "unknown")
            starttls_results[r] = starttls_results.get(r, 0) + 1

        return {
            "ports": ports,
            "connects": len(connects),
            "disconnects": len(disconnects),
            "auth_plain": len(auth_plain),
            "auth_tls": len(auth_tls),
            "starttls": len(starttls),
            "starttls_results": starttls_results,
            "last_ts": int(proto_hits[-1].get("ts", 0)) if proto_hits else None,
        }

    smtp = _proto_summary("smtp")
    imap = _proto_summary("imap")

    saw_plain = (smtp["auth_plain"] + imap["auth_plain"]) > 0
    saw_tls_auth = (smtp["auth_tls"] + imap["auth_tls"]) > 0
    saw_any_auth = saw_plain or saw_tls_auth

    connects_total = int(smtp["connects"]) + int(imap["connects"])
    disconnects_total = int(smtp["disconnects"]) + int(imap["disconnects"])
    retry_like = connects_total >= 6 and not saw_any_auth

    starttls_refused_like = (
        smtp["starttls_results"].get("refused", 0)
        + smtp["starttls_results"].get("drop_after_ready", 0)
        + smtp["starttls_results"].get("wrap_failed", 0)
        + imap["starttls_results"].get("refused", 0)
        + imap["starttls_results"].get("drop_after_ok", 0)
    )

    if saw_plain:
        verdict = "FAIL"
    elif saw_tls_auth:
        verdict = "PASS"
    else:
        verdict = "INCONCLUSIVE"

    return {
        "session": session,
        "events": hits,
        "verdict": verdict,
        "saw_plain": saw_plain,
        "saw_tls_auth": saw_tls_auth,
        "retry_like": retry_like,
        "starttls_refused_like": int(starttls_refused_like),
        "smtp": smtp,
        "imap": imap,
        "first_ts": int(hits[0].get("ts", 0)) if hits else None,
        "last_ts": int(hits[-1].get("ts", 0)) if hits else None,
    }


def create_app(hostname: str, store_path: Path, events_path: Path) -> FastAPI:
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        body = f"""
<h1>Mail Client Self-Test</h1>
<p class=\"muted\">Host: <code>{hostname}</code></p>
<div class=\"row\">{_mode_buttons()}</div>
<p class=\"muted\">This service generates a <b>session code</b>. Use the shown <b>username</b> in your mail client so results can be matched even behind NAT/shared IPs.</p>
<p class=\"muted\"><b>Important:</b> selecting a testcase currently sets the mode for your <b>public IP address</b>. If you share an IP (same Wi-Fi / university / company network), another user can overwrite the selected testcase for that IP.</p>
"""
        return _html_page("Self-Test", body)

    @app.get("/start", response_class=HTMLResponse)
    def start(req: Request, mode: str = "baseline", ttl: int = 900) -> str:
        if mode not in {"baseline", "t1", "t2", "t3", "t4"}:
            return _html_page("Bad Request", "<h1>Invalid mode</h1>")
        if ttl < 60 or ttl > 3600:
            return _html_page("Bad Request", "<h1>Invalid ttl</h1><p>Use 60..3600 seconds.</p>")

        ip = _client_ip(req)
        session = _new_session_code()
        username = f"test-{session}"
        email_addr = f"{username}@{hostname}"

        data = _load_store(store_path)
        _prune_overrides(data)
        now = int(time.time())
        expires = now + ttl
        overrides = [o for o in data.get("overrides", []) if o.get("ip") != ip]
        overrides.append({"ip": ip, "mode": mode, "expires": expires, "session": session})
        data["overrides"] = overrides
        _save_store(store_path, data)

        body = f"""
<h1>Session started</h1>
<div class="glass-panel">
  <div class="kv">
    <div><b>Mode</b>: <span class="pill">{mode.upper()}</span></div>
    <div><b>Time remaining</b>: <code><span id="ttl-remaining">...</span></code> <a class="btn" id="ttl-extend" href="#">Extend +15m</a></div>
  </div>
  <div class="row"><b>Your public IP</b>: <code>{ip}</code></div>
  <div class="row muted"><b>Important:</b> the testcase selection is applied per <b>public IP</b>. If multiple users share the same IP, the testcase for that IP can be overwritten.</div>
</div>

<div class="grid-2" style="margin-top: 14px;">
  <div class="glass-panel">
    <h2>Credentials</h2>
    <div class="row"><b>Email address</b> (autodetect): <code>{email_addr}</code></div>
    <div class="row"><b>Username</b>: <code>{username}</code></div>
    <div class="row"><b>Password</b>: <code>test</code> <span class="muted">(any value; not stored)</span></div>
  </div>

  <div class="glass-panel">
    <h2>Setup method</h2>
    <div class="row"><label for="setup"><b>Select</b>:</label></div>
    <div class="row"><select id="setup" style="padding: 10px 12px; border-radius: 14px; width: 100%;">
      <option value="manual" selected>Manual configuration (paper-compatible)</option>
      <option value="srv">Autodetect without XML (DNS SRV)</option>
    </select></div>
    <div class="row muted">Tip: if SRV autodetect doesn't work in your client, use Manual.</div>
  </div>
</div>

<div class="glass-panel" style="margin-top: 14px;">
  <h2>Settings</h2>

  <div id="setup-manual">
    <div class="row muted"><b>Note:</b> many clients (e.g., Thunderbird) let you configure only <b>one</b> incoming and <b>one</b> outgoing server.</div>
    <div class="row"><b>Recommended (STARTTLS test, paper-default)</b>:</div>
    <div class="row"><b>IMAP</b>: host <code>{hostname}</code>, port <code>143</code>, security <b>STARTTLS</b></div>
    <div class="row"><b>SMTP (submission)</b>: host <code>{hostname}</code>, port <code>587</code>, security <b>STARTTLS</b></div>
    <div class="row" style="margin-top: 14px;"><b>Optional (implicit TLS variant)</b>:</div>
    <div class="row"><b>IMAPS</b>: host <code>{hostname}</code>, port <code>993</code>, security <b>SSL/TLS</b></div>
    <div class="row"><b>SMTPS</b>: host <code>{hostname}</code>, port <code>465</code>, security <b>SSL/TLS</b></div>
    <div class="row"><b>Optional</b>: <b>SMTP</b> host <code>{hostname}</code>, port <code>25</code>, security <b>STARTTLS</b> <span class="muted">(some clients don't use this)</span></div>
  </div>

  <div id="setup-srv" style="display:none">
    <div class="row">Use <b>autodetect</b> by entering the email address <code>{email_addr}</code> in your client.</div>
    <div class="row muted">This relies on DNS SRV records (no XML). Client support varies.</div>
    <pre>_imaps._tcp.{hostname}  PRI 0  WEIGHT 1  PORT 993  TARGET {hostname}.
_imap._tcp.{hostname}   PRI 0  WEIGHT 1  PORT 143  TARGET {hostname}.
_submissions._tcp.{hostname} PRI 0 WEIGHT 1 PORT 465 TARGET {hostname}.
_submission._tcp.{hostname}  PRI 0 WEIGHT 1 PORT 587 TARGET {hostname}.
_smtp._tcp.{hostname}   PRI 0  WEIGHT 1  PORT 25   TARGET {hostname}.</pre>
  </div>
</div>

<script>
  let expiresTs = {expires};
  const mode = "{mode}";
  const session = "{session}";
  const remainingEl = document.getElementById('ttl-remaining');
  const extendBtn = document.getElementById('ttl-extend');
  function fmt(seconds) {{
    if (seconds <= 0) return 'expired';
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return m.toString() + 'm ' + s.toString().padStart(2,'0') + 's';
  }}
  function tick() {{
    const now = Math.floor(Date.now() / 1000);
    const rem = Math.max(0, expiresTs - now);
    remainingEl.textContent = fmt(rem);
  }}
  async function extendTtl(ev) {{
    ev.preventDefault();
    try {{
      const r = await fetch(`/api/extend?mode=${{encodeURIComponent(mode)}}&session=${{encodeURIComponent(session)}}&add=900`);
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'extend failed');
      expiresTs = j.expires;
      tick();
    }} catch (e) {{
      remainingEl.textContent = 'extend failed';
    }}
  }}
  extendBtn.addEventListener('click', extendTtl);
  setInterval(tick, 1000);
  tick();

  const sel = document.getElementById('setup');
  const manual = document.getElementById('setup-manual');
  const srv = document.getElementById('setup-srv');
  function apply() {{
    const v = sel.value;
    manual.style.display = (v === 'manual') ? 'block' : 'none';
    srv.style.display = (v === 'srv') ? 'block' : 'none';
  }}
  sel.addEventListener('change', apply);
  apply();
</script>

<div class="glass-panel" style="margin-top: 14px;">
  <div class="row muted">After you try to login/send mail, come back and refresh the status page.</div>
  <div class="row"><a class="btn" href="/status?session={session}">Open status page</a> <a class="btn" href="/">Back</a></div>
</div>
"""
        return _html_page("Session", body)

    @app.get("/status", response_class=HTMLResponse)
    def status(session: str) -> str:
        events = _read_events(events_path)
        summary = _summarize_session(events, session)
        hits = summary["events"]
        last = hits[-1] if hits else None

        def _row(label: str, value: str) -> str:
            return f"<tr><th>{label}</th><td>{value}</td></tr>"

        rows = []
        rows.append(_row("Session", f"<code>{session}</code>"))
        rows.append(_row("Username", f"<code>test-{session}</code>"))
        rows.append(_row("Events observed", str(len(hits))))
        if last:
            rows.append(_row("Last event", f"<code>{last.get('event')}</code> ({last.get('proto')})"))
            rows.append(_row("TLS active", str(bool(last.get("tls")))))
            rows.append(_row("Client IP", f"<code>{last.get('client_ip')}</code>"))
            rows.append(_row("Mode", f"<code>{last.get('mode')}</code>"))
        else:
            rows.append(_row("Last event", "(none yet)"))

        verdict = str(summary.get("verdict"))
        if verdict == "FAIL":
            headline = "FAIL (plaintext credentials exposure observed)"
        elif verdict == "PASS":
            headline = "PASS (no plaintext credentials observed; TLS auth seen)"
        else:
            headline = "INCONCLUSIVE (no credentials observed yet)"

        smtp = summary.get("smtp", {})
        imap = summary.get("imap", {})
        retry_like = bool(summary.get("retry_like"))
        starttls_refused_like = int(summary.get("starttls_refused_like") or 0)

        details = []
        details.append(f"<div class=\"row\"><b>Verdict</b>: <span class=\"pill\">{headline}</span></div>")
        details.append(
            "<div class=\"row muted\"><b>FAIL</b> only triggers when the service observes an auth/login attempt with <code>tls=false</code>." "</div>"
        )
        if verdict == "INCONCLUSIVE":
            details.append(
                "<div class=\"row muted\">No auth/login attempt was observed. This often means the client aborted earlier (e.g., due to TLS errors) or got stuck retrying.</div>"
            )
        if retry_like:
            details.append(
                "<div class=\"row muted\"><b>Retry loop hint:</b> multiple reconnects were observed without reaching authentication. This can happen if the client keeps trying different settings.</div>"
            )
        if starttls_refused_like > 0:
            details.append(
                "<div class=\"row muted\"><b>STARTTLS disruption observed:</b> the client attempted STARTTLS and the server refused/dropped it (testcase behavior). Some clients may respond by suggesting insecure changes.</div>"
            )

        if verdict in {"INCONCLUSIVE", "PASS"}:
            details.append(
                "<div class=\"glass-panel\" style=\"margin-top: 12px;\">"
                "<h2>If you saw no clear result, check your client UI</h2>"
                "<div class=\"row muted\">If your client shows prompts like these, that is a <b>security-relevant downgrade signal</b> even if we did not observe plaintext credentials on the wire:</div>"
                "<div class=\"row\">- Suggesting to <b>disable STARTTLS</b> / use <b>no encryption</b></div>"
                "<div class=\"row\">- Suggesting to change security from <b>STARTTLS</b> to <b>None</b></div>"
                "<div class=\"row\">- Suggesting to accept an <b>insecure connection</b> to proceed</div>"
                "<div class=\"row muted\">If you see such prompts, please do <b>not</b> follow them. Take a screenshot and report it as a downgrade indication.</div>"
                "</div>"
            )

        table = "<table>" + "".join(rows) + "</table>"
        proto_table = (
            "<table>"
            + "".join(
                [
                    "<tr><th>Protocol</th><th>Ports</th><th>Connects</th><th>Disconnects</th><th>STARTTLS</th><th>Auth (TLS)</th><th>Auth (plain)</th></tr>",
                    f"<tr><td>IMAP</td><td><code>{imap.get('ports')}</code></td><td>{imap.get('connects')}</td><td>{imap.get('disconnects')}</td><td>{imap.get('starttls')} <span class=\"muted\">{json.dumps(imap.get('starttls_results', {}))}</span></td><td>{imap.get('auth_tls')}</td><td>{imap.get('auth_plain')}</td></tr>",
                    f"<tr><td>SMTP</td><td><code>{smtp.get('ports')}</code></td><td>{smtp.get('connects')}</td><td>{smtp.get('disconnects')}</td><td>{smtp.get('starttls')} <span class=\"muted\">{json.dumps(smtp.get('starttls_results', {}))}</span></td><td>{smtp.get('auth_tls')}</td><td>{smtp.get('auth_plain')}</td></tr>",
                ]
            )
            + "</table>"
        )

        body = f"""
<h1>Status</h1>
<div class="glass-panel">{''.join(details)}</div>
<div style="margin-top: 12px;">{table}</div>

<h2>Protocol summary</h2>
{proto_table}

<h2>Recent events</h2>
<pre>{json.dumps(hits[-40:], indent=2)}</pre>

<div class=\"row\"><a class=\"btn\" href=\"/status?session={session}\">Refresh</a> <a class=\"btn\" href=\"/\">Back</a></div>
"""
        return _html_page("Status", body)

    @app.get("/api/health")
    def api_health() -> dict[str, Any]:
        return {"ok": True, "status": "up"}

    @app.get("/api/extend")
    def api_extend(req: Request, mode: str, session: str, add: int = 900) -> JSONResponse:
        if mode not in {"baseline", "t1", "t2", "t3", "t4"}:
            return JSONResponse({"ok": False, "error": "invalid mode"}, status_code=int(HTTPStatus.BAD_REQUEST))
        if add < 60 or add > 3600:
            return JSONResponse({"ok": False, "error": "invalid add"}, status_code=int(HTTPStatus.BAD_REQUEST))

        ip = _client_ip(req)
        now = int(time.time())
        data = _load_store(store_path)
        _prune_overrides(data)

        overrides: list[dict[str, Any]] = []
        cur_expires: Optional[int] = None
        cur_session: Optional[str] = None
        for o in data.get("overrides", []):
            if o.get("ip") == ip:
                cur_expires = int(o.get("expires", 0))
                s = o.get("session")
                cur_session = str(s) if s is not None else None
                continue
            overrides.append(o)

        base = max(cur_expires or 0, now)
        new_expires = base + int(add)
        hard_cap = now + 3600
        if new_expires > hard_cap:
            new_expires = hard_cap

        overrides.append({"ip": ip, "mode": mode, "expires": new_expires, "session": (cur_session or session)})
        data["overrides"] = overrides
        _save_store(store_path, data)

        return JSONResponse({"ok": True, "session": session, "mode": mode, "expires": new_expires, "remaining": max(0, new_expires - now)})

    @app.get("/api/session/{session}")
    def api_session(session: str) -> JSONResponse:
        events = _read_events(events_path)
        summary = _summarize_session(events, session)
        return JSONResponse({"ok": True, "session": session, "verdict": summary.get("verdict"), "summary": {"smtp": summary.get("smtp"), "imap": summary.get("imap"), "retry_like": summary.get("retry_like"), "starttls_refused_like": summary.get("starttls_refused_like"), "saw_plain": summary.get("saw_plain"), "saw_tls_auth": summary.get("saw_tls_auth")}, "events": summary.get("events", [])[-200:]})

    @app.exception_handler(Exception)
    def _err(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=int(HTTPStatus.INTERNAL_SERVER_ERROR))

    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--hostname", default="selftest.nsipmail.de")
    ap.add_argument("--store", default="/var/lib/nsip-selftest/mode.json")
    ap.add_argument("--events", default="/var/log/nsip-selftest/events.jsonl")
    args = ap.parse_args()

    app = create_app(args.hostname, Path(args.store), Path(args.events))

    import uvicorn  # local import

    uvicorn.run(app, host=args.listen_host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
