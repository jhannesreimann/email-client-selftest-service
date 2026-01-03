#!/usr/bin/env python3

import argparse
import json
import os
import secrets
import socket
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


def _load_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"default_mode": "baseline", "overrides": [], "guided_runs": {}}
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


def _guided_steps() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    out.append({"scenario": "immediate", "mode": "baseline", "label": "Baseline"})
    for m in ["t1", "t2", "t3", "t4"]:
        out.append({"scenario": "immediate", "mode": m, "label": f"Immediate {m.upper()}"})
    for m in ["t1", "t2", "t3", "t4"]:
        out.append({"scenario": "two_phase", "mode": m, "label": f"Two-phase {m.upper()}"})
    return out


def _guided_new_run_id() -> str:
    return "".join(ch for ch in secrets.token_urlsafe(12) if ch.isalnum())[:16]


def _guided_findings(summary: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if bool(summary.get("saw_plain")):
        out.append("plaintext_auth")
    if bool(summary.get("saw_tls_auth")):
        out.append("tls_auth")
    if bool(summary.get("retry_like")):
        out.append("retry_like")
    if int(summary.get("starttls_refused_like") or 0) > 0:
        out.append("starttls_disrupted")
    return out


def _guided_detect_post_activation(events: list[dict[str, Any]]) -> bool:
    auth_events = {"auth_command", "auth_login", "login_command"}
    first_auth_idx: Optional[int] = None
    for i, e in enumerate(events):
        if e.get("event") in auth_events and e.get("tls") is True:
            first_auth_idx = i
            break
    if first_auth_idx is None:
        return False
    for e in events[first_auth_idx + 1 :]:
        if e.get("event") in {"connect", "starttls", "disrupt", "drop", "disconnect"}:
            return True
    return False


def _guided_milestones(step: dict[str, Any], summary: dict[str, Any]) -> list[dict[str, Any]]:
    smtp = summary.get("smtp", {})
    imap = summary.get("imap", {})
    retry_like = bool(summary.get("retry_like"))
    starttls_refused_like = int(summary.get("starttls_refused_like") or 0)
    saw_any_auth = bool(summary.get("saw_plain")) or bool(summary.get("saw_tls_auth"))

    imap_connect = int(imap.get("connects") or 0) >= 1
    smtp_attempt = int(smtp.get("connects") or 0) >= 1
    imap_activity = saw_any_auth or int(imap.get("starttls") or 0) > 0 or retry_like or starttls_refused_like > 0

    milestones: list[dict[str, Any]] = []
    milestones.append({"key": "imap_connect", "ok": imap_connect, "label": "IMAP connection observed"})
    milestones.append({"key": "imap_activity", "ok": imap_activity, "label": "IMAP activity observed"})

    if str(step.get("scenario")) == "two_phase":
        activation = bool(summary.get("saw_tls_auth"))
        post_activation = _guided_detect_post_activation(list(summary.get("events") or []))
        milestones.append({"key": "activation", "ok": activation, "label": "Successful TLS login observed"})
        milestones.append({"key": "post_activation", "ok": post_activation, "label": "Follow-up attempt after login observed"})

    milestones.append({"key": "smtp_attempt", "ok": smtp_attempt, "label": "SMTP connection observed"})
    return milestones


def _guided_step_progress(step: dict[str, Any], summary: dict[str, Any], prev: dict[str, bool]) -> tuple[float, Optional[str], dict[str, bool], list[str]]:
    milestones = _guided_milestones(step, summary)
    keys = [str(m["key"]) for m in milestones]
    now_flags: dict[str, bool] = {k: False for k in keys}
    for m in milestones:
        now_flags[str(m["key"])] = bool(m.get("ok"))

    total = len(keys)
    done = sum(1 for k in keys if now_flags.get(k))
    fill = (done / total) if total else 0.0

    reason: Optional[str] = None
    for m in milestones:
        k = str(m["key"])
        if bool(m.get("ok")) and not bool(prev.get(k)):
            reason = str(m.get("label") or k)

    missing = [str(m.get("label") or m.get("key")) for m in milestones if not bool(m.get("ok"))]
    return min(0.99, max(0.0, fill)), reason, now_flags, missing


def _guided_set_override(data: dict[str, Any], ip: str, mode: str, scenario: str, session: str, ttl: int = 900) -> int:
    now = int(time.time())
    expires = now + int(ttl)
    overrides = [o for o in data.get("overrides", []) if o.get("ip") != ip]
    overrides.append({"ip": ip, "mode": mode, "expires": expires, "session": session, "scenario": scenario})
    data["overrides"] = overrides
    return expires


def _esc_html(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _guided_results_html(run: dict[str, Any]) -> str:
    steps = list(run.get("steps") or [])
    rows: list[str] = []
    rows.append("<tr><th>#</th><th>Scenario</th><th>Testcase</th><th>Verdict</th><th>Findings</th><th>Details</th></tr>")
    for i, s in enumerate(steps):
        res = s.get("result") or {}
        verdict = str(res.get("verdict") or "INCONCLUSIVE")
        findings = list(res.get("findings") or [])
        findings_html = " ".join([f"<span class=\"badge\">{_esc_html(str(f))}</span>" for f in findings])
        if not findings_html:
            findings_html = "<span class=\"muted\">(none)</span>"

        detail = res.get("detail") or {}
        smtp = detail.get("smtp") or {}
        imap = detail.get("imap") or {}
        detail_html = (
            "<details>"
            "<summary>Show</summary>"
            + f"<div class=\"row muted\"><b>IMAP</b> connects={_esc_html(str(imap.get('connects')))} starttls={_esc_html(str(imap.get('starttls_results')))} auth_tls={_esc_html(str(imap.get('auth_tls')))} auth_plain={_esc_html(str(imap.get('auth_plain')))}</div>"
            + f"<div class=\"row muted\"><b>SMTP</b> connects={_esc_html(str(smtp.get('connects')))} starttls={_esc_html(str(smtp.get('starttls_results')))} auth_tls={_esc_html(str(smtp.get('auth_tls')))} auth_plain={_esc_html(str(smtp.get('auth_plain')))}</div>"
            "</details>"
        )

        rows.append(
            "<tr>"
            + f"<td>{i+1}</td>"
            + f"<td><code>{_esc_html(str(s.get('scenario') or ''))}</code></td>"
            + f"<td><code>{_esc_html(str(s.get('mode') or ''))}</code></td>"
            + f"<td><span class=\"pill\">{_esc_html(verdict)}</span></td>"
            + f"<td>{findings_html}</td>"
            + f"<td>{detail_html}</td>"
            + "</tr>"
        )

    headline = "COMPLETED" if run.get("status") == "completed" else "ABORTED"
    return f"<h2>{headline}</h2><table>" + "".join(rows) + "</table>"


_BASE_TEMPLATE: Optional[str] = None


def _html_page(title: str, body_html: str) -> str:
    global _BASE_TEMPLATE
    if _BASE_TEMPLATE is None:
        base_path = Path(__file__).resolve().parent / "templates" / "base.html"
        _BASE_TEMPLATE = base_path.read_text(encoding="utf-8")
    return _BASE_TEMPLATE.replace("__TITLE__", title).replace("__BODY__", body_html)


def _mode_buttons() -> str:
    def _card(mode: str, label: str) -> str:
        return (
            """
<div class="mode-card">
  <a class="btn mode-start" href="/start?mode=__MODE__">Start __LABEL__</a>
  <button class="mode-info" type="button" data-mode="__MODE__" aria-label="Info">i</button>
</div>
""".replace("__MODE__", mode).replace("__LABEL__", label)
        )

    baseline = _card("baseline", "BASELINE")
    tests = "\n".join([_card(m, m.upper()) for m in ["t1", "t2", "t3", "t4"]])
    return (
        '<div class="mode-baseline">'
        + baseline
        + "</div>"
        + '<div class="mode-grid mode-grid-tests">'
        + tests
        + "</div>"
    )


def _mode_buttons_for_scenario(scenario: str) -> str:
    def _card(mode: str, label: str) -> str:
        return (
            (
                """
<div class="mode-card">
  <a class="btn mode-start" href="/start?scenario=__SCENARIO__&mode=__MODE__">Start __LABEL__</a>
  <button class="mode-info" type="button" data-mode="__MODE__" aria-label="Info">i</button>
</div>
"""
            )
            .replace("__SCENARIO__", scenario)
            .replace("__MODE__", mode)
            .replace("__LABEL__", label)
        )

    baseline = _card("baseline", "BASELINE")
    tests = "\n".join([_card(m, m.upper()) for m in ["t1", "t2", "t3", "t4"]])
    return (
        '<div class="mode-baseline">'
        + baseline
        + "</div>"
        + '<div class="mode-grid mode-grid-tests">'
        + tests
        + "</div>"
    )


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
    def _matches_session(e: dict[str, Any]) -> bool:
        if e.get("session") == session:
            return True
        if e.get("session") is None and e.get("override_session") == session:
            return True
        return False

    hits = [e for e in events if _matches_session(e)]
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


def create_app(hostname: str, autodetect_domain: str, store_path: Path, events_path: Path) -> FastAPI:
    app = FastAPI()

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index(view: str = "", scenario: str = "") -> str:
        view = (view or "").strip().lower()
        scenario = (scenario or "").strip().lower()
        if scenario not in {"", "immediate", "two_phase"}:
            scenario = ""

        if not view and scenario:
            view = "advanced"

        if view not in {"", "advanced"}:
            view = ""

        if not view:
            chooser = f"""
<h1>Mail Client Self-Test</h1>
<p class=\"muted\">WebUI host: <code>{hostname}</code></p>
<p class=\"muted\">Autodetect domain: <code>{autodetect_domain}</code></p>

<div class=\"glass-panel\" style=\"margin-top: 14px;\">\
  <h2>Choose view</h2>\
  <div class=\"row muted\">Guided runs the full suite automatically. Advanced lets you select scenario and testcase manually.</div>\
  <div class=\"grid-2\" style=\"margin-top: 12px;\">\
    <div class=\"mode-card\">\
      <a class=\"btn mode-start\" href=\"/guided\">Guided</a>\
    </div>\
    <div class=\"mode-card\">\
      <a class=\"btn mode-start\" href=\"/?view=advanced\">Advanced</a>\
    </div>\
  </div>\
</div>
"""
            return _html_page("Self-Test", chooser)

        scenario_choice = ""
        if not scenario:
            scenario_choice = f"""
<h1>Mail Client Self-Test</h1>
<p class=\"muted\">WebUI host: <code>{hostname}</code></p>
<p class=\"muted\">Autodetect domain: <code>{autodetect_domain}</code></p>

<div class=\"glass-panel\" style=\"margin-top: 14px;\">
  <h2>Choose scenario</h2>
  <div class=\"row muted\">Select how the testcase should be applied: immediately during setup/autodetect, or only after the first successful login.</div>
  <div class=\"grid-2\" style=\"margin-top: 12px;\">
    <div class=\"mode-card\">
      <a class=\"btn mode-start\" href=\"/?scenario=immediate\">Immediate</a>
      <button class=\"mode-info scenario-info\" type=\"button\" data-scenario=\"immediate\" aria-label=\"Info\">i</button>
    </div>
    <div class=\"mode-card\">
      <a class=\"btn mode-start\" href=\"/?scenario=two_phase\">Two-phase</a>
      <button class=\"mode-info scenario-info\" type=\"button\" data-scenario=\"two_phase\" aria-label=\"Info\">i</button>
    </div>
  </div>
  <div class=\"row muted\" style=\"margin-top: 10px;\">You will select the testcase mode on the next step.</div>
</div>
"""

        body = """
__SCENARIO_CHOICE__
__MODE_SELECTION__
<p class="muted">This service generates a <b>session code</b>. Use the shown <b>username</b> in your mail client so results can be matched even behind NAT/shared IPs.</p>
<p class="muted"><b>Important:</b> selecting a testcase currently sets the mode for your <b>public IP address</b>. If you share an IP (same Wi-Fi / university / company network), another user can overwrite the selected testcase for that IP.</p>

<div id="mode-modal" class="modal-backdrop" style="display:none">
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title" id="mode-modal-title">Info</div>
      <button class="modal-close" id="mode-modal-close" type="button" aria-label="Close">×</button>
    </div>
    <div class="modal-body" id="mode-modal-body"></div>
  </div>
</div>

<script>
  const SCENARIO_INFO = {
    immediate: {
      title: 'Immediate scenario',
      html: `<div class="row"><b>Attack scenario:</b> an active attacker (MITM) is already present during account setup / autodetect, so the testcase affects what the client decides and stores as its security settings.</div><div class="row">The selected testcase is active immediately, including during autodetect / account setup.</div><div class="row muted"><b>Implication:</b> this is the stricter / more pessimistic scenario. If the client downgrades to insecure settings (e.g., chooses "No encryption" in T1) or sends credentials without TLS, the client is vulnerable to downgrade attacks during setup and may permanently store unsafe configuration. If the client still enforces TLS despite disruptions, it is more robust.</div>`
    },
    two_phase: {
      title: 'Two-phase scenario',
      html: `<div class="row"><b>Attack scenario:</b> initial setup happens without interference (you can complete a normal, secure login once). Only afterwards, an active attacker appears and tries to force downgrade / break STARTTLS on later connections.</div><div class="row">Setup behaves like BASELINE until your first successful login/auth for this session.</div><div class="row muted"><b>Implication:</b> this isolates the client's behavior after it already had a secure baseline. A secure client should refuse to send credentials without TLS even if STARTTLS is stripped/refused/broken later. If the client falls back to plaintext auth after the attacker appears, it is vulnerable to post-setup downgrade attacks (credentials exposure on subsequent reconnects/sends).</div>`
    }
  };

  const MODE_INFO = {
    baseline: {
      title: 'BASELINE',
      html: '<div class="row">Normal server behavior: STARTTLS is offered (where applicable) and AUTH/LOGIN is accepted.</div>'
    },
    t1: {
      title: 'T1 – STARTTLS not advertised',
      img: '/static/T1.png',
      html: '<div class="row">Simulation: the server does not advertise STARTTLS (capability stripping equivalent).</div>'
    },
    t2: {
      title: 'T2 – TLS negotiation disrupted',
      img: '/static/T2.png',
      html: '<div class="row">Simulation: the server accepts STARTTLS and then breaks the TLS negotiation (handshake failure-like).</div>'
    },
    t3: {
      title: 'T3 – STARTTLS refused',
      img: '/static/T3.png',
      html: '<div class="row">Simulation: STARTTLS is advertised but rejected when requested.</div>'
    },
    t4: {
      title: 'T4 – Post-handshake disruption',
      img: '/static/T4.png',
      html: '<div class="row">Simulation: TLS handshake succeeds, then the server injects unexpected data (e.g., NOOP) and closes.</div>'
    }
  };

  const modal = document.getElementById('mode-modal');
  const modalTitle = document.getElementById('mode-modal-title');
  const modalBody = document.getElementById('mode-modal-body');
  const modalClose = document.getElementById('mode-modal-close');

  function openModeInfo(mode) {
    const info = MODE_INFO[mode];
    if (!info) return;
    if (modal.parentElement !== document.body) {
      document.body.appendChild(modal);
    }
    modalTitle.textContent = info.title || mode;
    let body = info.html || '';
    if (info.img) {
      body = `<div class="modal-figure"><img class="mode-figure" src="${info.img}" alt="${info.title}" /></div>` + body;
    }
    modalBody.innerHTML = body;
    modal.style.display = 'flex';
  }

  function openScenarioInfo(scenario) {
    const info = SCENARIO_INFO[scenario];
    if (!info) return;
    if (modal.parentElement !== document.body) {
      document.body.appendChild(modal);
    }
    modalTitle.textContent = info.title || scenario;
    modalBody.innerHTML = info.html || '';
    modal.style.display = 'flex';
  }

  function closeModeInfo() {
    modal.style.display = 'none';
  }

  document.querySelectorAll('.mode-info').forEach((btn) => {
    btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      openModeInfo(btn.getAttribute('data-mode'));
    });
  });

  document.querySelectorAll('.scenario-info').forEach((btn) => {
    btn.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      openScenarioInfo(btn.getAttribute('data-scenario'));
    });
  });
  modalClose.addEventListener('click', closeModeInfo);
  modal.addEventListener('click', (ev) => {
    if (ev.target === modal) closeModeInfo();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeModeInfo();
  });
</script>
"""

        mode_selection = ""
        if scenario:
            mode_selection = f"""\
<div class=\"page-header\">\
  <h1>Mail Client Self-Test</h1>\
  <div class=\"page-actions\">\
    <span class=\"pill\">{scenario}</span>\
    <a class=\"icon-btn\" href=\"/\" aria-label=\"Back\" title=\"Back\">←</a>\
  </div>\
</div>\
<p class=\"muted\">WebUI host: <code>{hostname}</code></p>
<p class=\"muted\">Autodetect domain: <code>{autodetect_domain}</code></p>
<div class=\"row\">__MODE_BUTTONS__</div>
"""

        body = (
            body.replace("__SCENARIO_CHOICE__", scenario_choice)
            .replace("__MODE_SELECTION__", mode_selection)
            .replace("__MODE_BUTTONS__", _mode_buttons_for_scenario(scenario) if scenario else "")
        )
        return _html_page("Self-Test", body)

    @app.get("/guided", response_class=HTMLResponse)
    def guided() -> str:
        body = """
<div class="page-header">
  <h1>Guided Self-Test</h1>
  <div class="page-actions">
    <a class="icon-btn" href="/" aria-label="Back" title="Back">←</a>
  </div>
</div>

<div class="glass-panel">
  <div class="row"><b>Progress</b></div>
  <div class="progress-wrap"><div id="guided-progress" class="progress-fill" style="width:0%"></div></div>
  <div class="row muted" id="guided-progress-reason">Last progress: (none yet)</div>
</div>

<div class="glass-panel" style="margin-top: 12px;">
  <div class="row" id="guided-step-title"><b>Loading…</b></div>
  <div class="row muted" id="guided-step-instructions"></div>
  <div id="guided-credentials" style="margin-top: 10px;"></div>
  <div id="guided-manual" style="margin-top: 10px; display:none;"></div>
  <div class="row" style="margin-top: 12px; display:flex; gap:10px; flex-wrap:wrap;">
    <a class="btn btn-cta" id="guided-confirm" href="#">I did the steps</a>
    <a class="btn" id="guided-skip" href="#">Skip anyway</a>
    <a class="btn" id="guided-abort" href="#">Abort</a>
  </div>
  <div class="row muted" id="guided-errors" style="margin-top: 10px;"></div>
</div>

<div class="glass-panel" style="margin-top: 12px; display:none;" id="guided-results"></div>

<script>
  let runId = null;

  function pct(x) {
    return Math.max(0, Math.min(100, Math.round((x || 0) * 10000) / 100));
  }

  async function api(path, method='GET') {
    const r = await fetch(path, {method});
    return await r.json();
  }

  function setDisabled(el, disabled) {
    if (!el) return;
    if (disabled) el.classList.add('btn-disabled');
    else el.classList.remove('btn-disabled');
  }

  function render(st) {
    const prog = document.getElementById('guided-progress');
    const reason = document.getElementById('guided-progress-reason');
    const title = document.getElementById('guided-step-title');
    const instr = document.getElementById('guided-step-instructions');
    const creds = document.getElementById('guided-credentials');
    const manual = document.getElementById('guided-manual');
    const confirmBtn = document.getElementById('guided-confirm');
    const skipBtn = document.getElementById('guided-skip');
    const abortBtn = document.getElementById('guided-abort');
    const errs = document.getElementById('guided-errors');
    const results = document.getElementById('guided-results');

    prog.style.width = `${pct(st.progress)}%`;
    reason.textContent = `Last progress: ${st.last_progress_reason || '(none yet)'}`;
    errs.textContent = st.error || '';

    if (st.status === 'completed' || st.status === 'aborted') {
      title.innerHTML = `<b>${(st.status || '').toUpperCase()}</b>`;
      instr.textContent = '';
      creds.innerHTML = '';
      manual.style.display = 'none';
      setDisabled(confirmBtn, true);
      setDisabled(skipBtn, true);
      setDisabled(abortBtn, true);
      if (st.results_html) {
        results.style.display = 'block';
        results.innerHTML = st.results_html;
      }
      return;
    }

    title.innerHTML = `<b>Step ${st.step_index + 1}/9:</b> ${st.step_label || ''}`;
    instr.innerHTML = st.instructions_html || '';
    creds.innerHTML = st.credentials_html || '';
    if (st.show_manual) {
      manual.style.display = 'block';
      manual.innerHTML = st.manual_html || '';
    } else {
      manual.style.display = 'none';
    }
    setDisabled(confirmBtn, !st.ready);
  }

  async function poll() {
    if (!runId) return;
    const st = await api(`/api/guided/run/${encodeURIComponent(runId)}`);
    if (!st.ok) {
      document.getElementById('guided-errors').textContent = st.error || 'poll failed';
      return;
    }
    render(st);
  }

  async function start() {
    const r = await api('/api/guided/run/start', 'POST');
    if (!r.ok) {
      document.getElementById('guided-errors').textContent = r.error || 'start failed';
      return;
    }
    runId = r.run_id;
    await poll();
    setInterval(poll, 1200);
  }

  document.getElementById('guided-confirm').addEventListener('click', async (ev) => {
    ev.preventDefault();
    if (!runId) return;
    if (ev.target.classList.contains('btn-disabled')) return;
    const r = await api(`/api/guided/run/${encodeURIComponent(runId)}/confirm`, 'POST');
    if (!r.ok) document.getElementById('guided-errors').textContent = r.error || 'confirm failed';
    await poll();
  });

  document.getElementById('guided-skip').addEventListener('click', async (ev) => {
    ev.preventDefault();
    if (!runId) return;
    if (!confirm('Skip this step anyway?')) return;
    const r = await api(`/api/guided/run/${encodeURIComponent(runId)}/skip`, 'POST');
    if (!r.ok) document.getElementById('guided-errors').textContent = r.error || 'skip failed';
    await poll();
  });

  document.getElementById('guided-abort').addEventListener('click', async (ev) => {
    ev.preventDefault();
    if (!runId) return;
    if (!confirm('Abort the guided run?')) return;
    const r = await api(`/api/guided/run/${encodeURIComponent(runId)}/abort`, 'POST');
    if (!r.ok) document.getElementById('guided-errors').textContent = r.error || 'abort failed';
    await poll();
  });

  start();
</script>
"""
        return _html_page("Guided", body)

    @app.get("/start", response_class=HTMLResponse)
    def start(req: Request, mode: str = "baseline", ttl: int = 900, scenario: str = "immediate") -> str:
        if mode not in {"baseline", "t1", "t2", "t3", "t4"}:
            return _html_page("Bad Request", "<h1>Invalid mode</h1>")
        if ttl < 60 or ttl > 3600:
            return _html_page("Bad Request", "<h1>Invalid ttl</h1><p>Use 60..3600 seconds.</p>")

        scenario = (scenario or "").strip().lower()
        if scenario not in {"immediate", "two_phase"}:
            return _html_page("Bad Request", "<h1>Invalid scenario</h1>")

        ip = _client_ip(req)
        session = _new_session_code()
        username = f"test-{session}"
        email_addr = f"{username}@{autodetect_domain}"
        imap_host = f"imap.{autodetect_domain}"
        smtp_host = f"smtp.{autodetect_domain}"

        data = _load_store(store_path)
        _prune_overrides(data)
        now = int(time.time())
        expires = now + ttl
        overrides = [o for o in data.get("overrides", []) if o.get("ip") != ip]
        overrides.append({"ip": ip, "mode": mode, "expires": expires, "session": session, "scenario": scenario})
        data["overrides"] = overrides
        _save_store(store_path, data)

        body = f"""
<div class="page-header">
  <h1>Session started</h1>
  <div class="page-actions">
    <a class="icon-btn" href="/" aria-label="Back" title="Back">←</a>
  </div>
</div>
<div class="glass-panel">
  <div class="kv">
    <div><b>Mode</b>: <span class="pill">{mode.upper()}</span></div>
    <div><b>Scenario</b>: <span class="pill">{scenario}</span></div>
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
      <option value="manual" selected>Manual configuration (recommended)</option>
      <option value="autodetect">Autodetect (enter email address)</option>
    </select></div>
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

  <div id="setup-autodetect" style="display:none">
    <div class="row">Enter this email address in your client: <code>{email_addr}</code></div>
    <div class="row muted">The client should discover <code>{imap_host}</code> / <code>{smtp_host}</code>. If it proposes different providers/settings, switch to <b>Manual configuration</b> and use the settings above.</div>
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
  const autodetect = document.getElementById('setup-autodetect');
  function apply() {{
    const v = sel.value;
    manual.style.display = (v === 'manual') ? 'block' : 'none';
    autodetect.style.display = (v === 'autodetect') ? 'block' : 'none';
  }}
  sel.addEventListener('change', apply);
  apply();

</script>

<script src="/static/toasts.js"></script>
<script>initToasts({json.dumps(session)});</script>

<div class="glass-panel" style="margin-top: 14px;">
  <div class="row muted">Open the status page now, then configure your mail client and try to login/send mail.</div>
  <div class="row"><a class="btn btn-cta" href="/status?session={session}">Open status page</a></div>
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
<div class="page-header">
  <h1>Status</h1>
  <div class="page-actions">
    <a class="icon-btn" href="/status?session={session}" aria-label="Reload" title="Reload">↻</a>
    <a class="icon-btn" href="/" aria-label="Back" title="Back">←</a>
  </div>
</div>

<div class="glass-panel">{''.join(details)}</div>
<div style="margin-top: 12px;">{table}</div>

<h2>Protocol summary</h2>
{proto_table}

<h2>Recent events</h2>
<div class="glass-panel" style="max-height: 420px; overflow-y: auto; overflow-x: auto;">
  <pre style="margin: 0;">{json.dumps(hits[-40:], indent=2)}</pre>
</div>

<script src="/static/toasts.js"></script>
<script>initToasts({json.dumps(session)});</script>
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
        cur_scenario: Optional[str] = None
        cur_activated: Optional[bool] = None
        for o in data.get("overrides", []):
            if o.get("ip") == ip:
                cur_expires = int(o.get("expires", 0))
                s = o.get("session")
                cur_session = str(s) if s is not None else None
                cur_scenario = str(o.get("scenario") or "") or None
                if "activated" in o:
                    cur_activated = bool(o.get("activated"))
                continue
            overrides.append(o)

        base = max(cur_expires or 0, now)
        new_expires = base + int(add)
        hard_cap = now + 3600
        if new_expires > hard_cap:
            new_expires = hard_cap

        entry: dict[str, Any] = {"ip": ip, "mode": mode, "expires": new_expires, "session": (cur_session or session)}
        if cur_scenario is not None:
            entry["scenario"] = cur_scenario
        if cur_activated is not None:
            entry["activated"] = cur_activated
        overrides.append(entry)
        data["overrides"] = overrides
        _save_store(store_path, data)

        return JSONResponse({"ok": True, "session": session, "mode": mode, "expires": new_expires, "remaining": max(0, new_expires - now)})

    @app.get("/api/session/{session}")
    def api_session(session: str) -> JSONResponse:
        events = _read_events(events_path)
        summary = _summarize_session(events, session)
        return JSONResponse({"ok": True, "session": session, "verdict": summary.get("verdict"), "summary": {"smtp": summary.get("smtp"), "imap": summary.get("imap"), "retry_like": summary.get("retry_like"), "starttls_refused_like": summary.get("starttls_refused_like"), "saw_plain": summary.get("saw_plain"), "saw_tls_auth": summary.get("saw_tls_auth")}, "events": summary.get("events", [])[-200:]})

    def _guided_get_run(data: dict[str, Any], run_id: str) -> Optional[dict[str, Any]]:
        data.setdefault("guided_runs", {})
        run = data["guided_runs"].get(run_id)
        if not isinstance(run, dict):
            return None
        return run

    def _guided_current_step(run: dict[str, Any]) -> Optional[dict[str, Any]]:
        idx = int(run.get("step_index") or 0)
        steps = list(run.get("steps") or [])
        if idx < 0 or idx >= len(steps):
            return None
        step = steps[idx]
        if not isinstance(step, dict):
            return None
        return step

    def _guided_step_credentials_html(session: str) -> str:
        username = f"test-{session}"
        email_addr = f"{username}@{autodetect_domain}"
        return (
            "<div class=\"glass-panel\">"
            "<h2>Credentials</h2>"
            + f"<div class=\"row\"><b>Email</b> (autodetect): <code>{_esc_html(email_addr)}</code></div>"
            + f"<div class=\"row\"><b>Username</b>: <code>{_esc_html(username)}</code></div>"
            + "<div class=\"row\"><b>Password</b>: <code>test</code></div>"
            "</div>"
        )

    def _guided_manual_html() -> str:
        return (
            "<div class=\"glass-panel\">"
            "<h2>Manual settings</h2>"
            + f"<div class=\"row\"><b>IMAP</b>: host <code>{_esc_html(hostname)}</code>, port <code>143</code>, security <b>STARTTLS</b></div>"
            + f"<div class=\"row\"><b>SMTP</b>: host <code>{_esc_html(hostname)}</code>, port <code>587</code>, security <b>STARTTLS</b></div>"
            + "<div class=\"row muted\">SMTP is required: please attempt to send a test mail in every step.</div>"
            "</div>"
        )

    def _guided_instructions_html(step: dict[str, Any]) -> str:
        scenario = str(step.get("scenario") or "")
        mode = str(step.get("mode") or "")
        base = "<div class=\"row\">1) Add this account via autodetect (enter the email above).</div>"
        base += "<div class=\"row\">2) Try to login / refresh inbox.</div>"
        base += "<div class=\"row\">3) Try to send a test mail (SMTP attempt is required).</div>"
        if scenario == "two_phase":
            base += "<div class=\"row muted\">Two-phase: first login should succeed; then trigger another refresh/send so the disruption happens after activation.</div>"
        if mode == "baseline":
            base += "<div class=\"row muted\">Baseline sanity check: should normally login over STARTTLS and not expose plaintext credentials.</div>"
        else:
            base += "<div class=\"row muted\">Do not accept insecure downgrade prompts (e.g., \"No encryption\").</div>"
        return base

    @app.post("/api/guided/run/start")
    def api_guided_start(req: Request) -> JSONResponse:
        ip = _client_ip(req)
        run_id = _guided_new_run_id()
        steps = _guided_steps()

        data = _load_store(store_path)
        _prune_overrides(data)
        data.setdefault("guided_runs", {})

        step0 = dict(steps[0])
        session0 = _new_session_code()
        step0["session"] = session0
        step0["created_ts"] = int(time.time())
        step0["milestones"] = {}
        step0["step_progress"] = 0.0
        step0["last_progress_reason"] = None

        expires0 = _guided_set_override(data, ip, str(step0["mode"]), str(step0["scenario"]), session0, ttl=900)
        step0["expires"] = expires0

        run = {
            "run_id": run_id,
            "ip": ip,
            "created_ts": int(time.time()),
            "status": "running",
            "step_index": 0,
            "steps": [step0] + [dict(s) for s in steps[1:]],
            "last_progress_reason": None,
            "last_progress": 0.0,
        }
        data["guided_runs"][run_id] = run
        _save_store(store_path, data)
        return JSONResponse({"ok": True, "run_id": run_id})

    def _guided_finish_step(step: dict[str, Any], summary: dict[str, Any], forced_verdict: Optional[str] = None) -> None:
        verdict = str(forced_verdict or summary.get("verdict") or "INCONCLUSIVE")
        step["result"] = {
            "verdict": verdict,
            "findings": _guided_findings(summary),
            "detail": {
                "smtp": summary.get("smtp"),
                "imap": summary.get("imap"),
                "retry_like": summary.get("retry_like"),
                "starttls_refused_like": summary.get("starttls_refused_like"),
            },
        }
        step["finished_ts"] = int(time.time())

    def _guided_advance_run(data: dict[str, Any], run: dict[str, Any]) -> None:
        ip = str(run.get("ip") or "")
        steps = list(run.get("steps") or [])
        idx = int(run.get("step_index") or 0)
        idx += 1
        run["step_index"] = idx
        if idx >= len(steps):
            run["status"] = "completed"
            data["overrides"] = [o for o in data.get("overrides", []) if o.get("ip") != ip]
            return

        step = steps[idx]
        if not isinstance(step, dict):
            step = {}
            steps[idx] = step
        session = _new_session_code()
        step["session"] = session
        step["created_ts"] = int(time.time())
        step["milestones"] = {}
        step["step_progress"] = 0.0
        step["last_progress_reason"] = None

        expires = _guided_set_override(data, ip, str(step.get("mode") or "baseline"), str(step.get("scenario") or "immediate"), session, ttl=900)
        step["expires"] = expires
        run["steps"] = steps

    def _guided_state_response(data: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
        status = str(run.get("status") or "running")
        if status in {"completed", "aborted"}:
            return {
                "ok": True,
                "status": status,
                "progress": float(run.get("last_progress") or 0.0),
                "last_progress_reason": run.get("last_progress_reason"),
                "step_index": int(run.get("step_index") or 0),
                "results_html": _guided_results_html(run),
            }

        step = _guided_current_step(run)
        if step is None:
            return {"ok": False, "error": "invalid step"}
        session = str(step.get("session") or "")
        if not session:
            return {"ok": False, "error": "missing session"}

        events = _read_events(events_path)
        summary = _summarize_session(events, session)

        prev = dict(step.get("milestones") or {})
        fill, reason, flags, missing = _guided_step_progress(step, summary, prev)
        if reason is not None:
            step["last_progress_reason"] = reason
            run["last_progress_reason"] = reason
        step["milestones"] = flags
        step["step_progress"] = float(fill)

        idx = int(run.get("step_index") or 0)
        completed = idx
        overall = (completed / 9.0) + (float(fill) / 9.0)
        run["last_progress"] = float(overall)

        age = int(time.time()) - int(step.get("created_ts") or int(time.time()))
        total_connects = int(summary.get("imap", {}).get("connects") or 0) + int(summary.get("smtp", {}).get("connects") or 0)
        show_manual = total_connects <= 0 and age >= 25

        ready = all(bool(v) for v in flags.values()) if flags else False

        mode = str(step.get("mode") or "")
        scenario = str(step.get("scenario") or "")
        step_label = str(step.get("label") or "")

        resp: dict[str, Any] = {
            "ok": True,
            "status": status,
            "step_index": idx,
            "step_label": step_label,
            "scenario": scenario,
            "mode": mode,
            "progress": float(overall),
            "last_progress_reason": run.get("last_progress_reason"),
            "ready": bool(ready),
            "missing": missing,
            "instructions_html": _guided_instructions_html(step),
            "credentials_html": _guided_step_credentials_html(session),
            "show_manual": bool(show_manual),
            "manual_html": _guided_manual_html() if show_manual else "",
        }

        data.setdefault("guided_runs", {})
        data["guided_runs"][str(run.get("run_id"))] = run
        _save_store(store_path, data)
        return resp

    @app.get("/api/guided/run/{run_id}")
    def api_guided_get(req: Request, run_id: str) -> JSONResponse:
        ip = _client_ip(req)
        data = _load_store(store_path)
        run = _guided_get_run(data, run_id)
        if run is None:
            return JSONResponse({"ok": False, "error": "unknown run"}, status_code=int(HTTPStatus.NOT_FOUND))
        if str(run.get("ip")) != ip:
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=int(HTTPStatus.FORBIDDEN))
        resp = _guided_state_response(data, run)
        if not resp.get("ok"):
            return JSONResponse(resp, status_code=int(HTTPStatus.BAD_REQUEST))
        return JSONResponse(resp)

    @app.post("/api/guided/run/{run_id}/confirm")
    def api_guided_confirm(req: Request, run_id: str) -> JSONResponse:
        ip = _client_ip(req)
        data = _load_store(store_path)
        run = _guided_get_run(data, run_id)
        if run is None:
            return JSONResponse({"ok": False, "error": "unknown run"}, status_code=int(HTTPStatus.NOT_FOUND))
        if str(run.get("ip")) != ip:
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=int(HTTPStatus.FORBIDDEN))
        if str(run.get("status")) != "running":
            return JSONResponse({"ok": False, "error": "not running"}, status_code=int(HTTPStatus.BAD_REQUEST))

        step = _guided_current_step(run)
        if step is None:
            return JSONResponse({"ok": False, "error": "invalid step"}, status_code=int(HTTPStatus.BAD_REQUEST))

        session = str(step.get("session") or "")
        events = _read_events(events_path)
        summary = _summarize_session(events, session)
        prev = dict(step.get("milestones") or {})
        fill, _, flags, missing = _guided_step_progress(step, summary, prev)
        step["milestones"] = flags
        step["step_progress"] = float(fill)
        ready = all(bool(v) for v in flags.values()) if flags else False
        if not ready:
            return JSONResponse({"ok": False, "error": "not ready", "missing": missing}, status_code=int(HTTPStatus.BAD_REQUEST))

        _guided_finish_step(step, summary)
        _guided_advance_run(data, run)
        data.setdefault("guided_runs", {})
        data["guided_runs"][run_id] = run
        _save_store(store_path, data)
        return JSONResponse({"ok": True})

    @app.post("/api/guided/run/{run_id}/skip")
    def api_guided_skip(req: Request, run_id: str) -> JSONResponse:
        ip = _client_ip(req)
        data = _load_store(store_path)
        run = _guided_get_run(data, run_id)
        if run is None:
            return JSONResponse({"ok": False, "error": "unknown run"}, status_code=int(HTTPStatus.NOT_FOUND))
        if str(run.get("ip")) != ip:
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=int(HTTPStatus.FORBIDDEN))
        if str(run.get("status")) != "running":
            return JSONResponse({"ok": False, "error": "not running"}, status_code=int(HTTPStatus.BAD_REQUEST))

        step = _guided_current_step(run)
        if step is None:
            return JSONResponse({"ok": False, "error": "invalid step"}, status_code=int(HTTPStatus.BAD_REQUEST))

        session = str(step.get("session") or "")
        events = _read_events(events_path)
        summary = _summarize_session(events, session)
        _guided_finish_step(step, summary, forced_verdict="INCONCLUSIVE")
        _guided_advance_run(data, run)
        data.setdefault("guided_runs", {})
        data["guided_runs"][run_id] = run
        _save_store(store_path, data)
        return JSONResponse({"ok": True})

    @app.post("/api/guided/run/{run_id}/abort")
    def api_guided_abort(req: Request, run_id: str) -> JSONResponse:
        ip = _client_ip(req)
        data = _load_store(store_path)
        run = _guided_get_run(data, run_id)
        if run is None:
            return JSONResponse({"ok": False, "error": "unknown run"}, status_code=int(HTTPStatus.NOT_FOUND))
        if str(run.get("ip")) != ip:
            return JSONResponse({"ok": False, "error": "forbidden"}, status_code=int(HTTPStatus.FORBIDDEN))
        if str(run.get("status")) not in {"running", "aborted"}:
            return JSONResponse({"ok": False, "error": "cannot abort"}, status_code=int(HTTPStatus.BAD_REQUEST))

        run["status"] = "aborted"
        run["aborted_ts"] = int(time.time())
        data["overrides"] = [o for o in data.get("overrides", []) if o.get("ip") != ip]
        run["last_progress"] = float(run.get("last_progress") or 0.0)
        data.setdefault("guided_runs", {})
        data["guided_runs"][run_id] = run
        _save_store(store_path, data)
        return JSONResponse({"ok": True})

    @app.exception_handler(Exception)
    def _err(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=int(HTTPStatus.INTERNAL_SERVER_ERROR))

    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--hostname", default="selftest.nsipmail.de")
    ap.add_argument("--autodetect-domain", default=(os.environ.get("NSIP_SELFTEST_AUTODETECT_DOMAIN") or ""))
    ap.add_argument("--store", default="/var/lib/nsip-selftest/mode.json")
    ap.add_argument("--events", default="/var/log/nsip-selftest/events.jsonl")
    args = ap.parse_args()

    autodetect_domain = args.autodetect_domain.strip()
    if not autodetect_domain:
        try:
            ip = socket.gethostbyname(args.hostname)
            if ip.count(".") == 3:
                autodetect_domain = f"{ip}.nip.io"
        except Exception:
            autodetect_domain = ""
    autodetect_domain = autodetect_domain or args.hostname

    app = create_app(args.hostname, autodetect_domain, Path(args.store), Path(args.events))

    import uvicorn  # local import

    uvicorn.run(app, host=args.listen_host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
