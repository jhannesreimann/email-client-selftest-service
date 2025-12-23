# Selftest Service (Public mail-client self-test)

This folder contains a **public self-test service** that helps determine whether a mail client can be coerced into **plaintext authentication** under STARTTLS disruption/downgrade-like conditions.

It is intended as a **server-side, client-facing self-test** (no local proxy / no mitmproxy on the user’s machine).

## What this is / what this is not

- **This is:** a small Python SMTP/IMAP service that can switch behavior between testcases (`baseline`, `t1`–`t4`) based on a mode store, plus a WebUI to start sessions and view results.
- **This is not:** the original local reproduction setup (mitmproxy-based) used for deeper protocol-level experiments.
- **This is not:** a real mailbox or mail relay. It does not deliver mail or provide mail storage.

## High-level architecture

- **Mail self-test server** (`selftest_server.py`)
  - Implements minimal **SMTP** and **IMAP** endpoints.
  - Chooses a testcase mode based on a shared JSON mode store (per public IP override + TTL).
  - Logs privacy-safe events to a JSONL file (no passwords).
  - Extracts a **session code** from the username (`test-SESSION`) so the WebUI can filter events.

- **WebUI** (`webui.py`, FastAPI)
  - Creates a session and sets the mode override for the user’s public IP (TTL-based).
  - Shows the session-coded username/email to configure in the mail client.
  - Displays observed SMTP/IMAP events for that session.
  - Shows a live TTL countdown and allows extending the TTL.

- **Nginx** (recommended for production)
  - Terminates HTTPS for the WebUI on TCP `443`.
  - Reverse proxies to the WebUI bound to `127.0.0.1:9000`.

## Ports / TLS behavior (paper-compatible)

The mail self-test server binds to **standard client ports** and supports both STARTTLS and implicit TLS:

| Protocol | Port | TLS style |
|---|---:|---|
| IMAP | 143 | STARTTLS |
| IMAP | 993 | implicit TLS (IMAPS) |
| SMTP | 25 | STARTTLS (optional; some clients don’t use it) |
| SMTP | 465 | implicit TLS (SMTPS) |
| SMTP | 587 | STARTTLS (submission) |

Notes:

- Ports `<1024` require root or capabilities.
- The server logs `server_port` per event so you can see which port the client used.

## Modes (testcases)

Modes approximate different disruption patterns:

- `baseline`: advertises STARTTLS (where applicable) and accepts AUTH/LOGIN.
- `t1`: does **not** advertise STARTTLS (capability stripping equivalent).
- `t2`: advertises STARTTLS, replies OK/Ready, then drops (approx handshake failure).
- `t3`: advertises STARTTLS but rejects the STARTTLS command.
- `t4`: completes TLS handshake, then disrupts the session by injecting unexpected data (e.g., `NOOP`) and closing.

## DNS setup (A-record based; no SRV)

This service intentionally **does not** provide Thunderbird Autoconfig XML.

The recommended way to run the self-test is **manual configuration** (paper-compatible and most reproducible).

For autodetect/heuristic setup, this deployment relies on **A records only** (SRV is intentionally not used).

Required A records:

- `selftest.nsipmail.de -> <public IP>`
- `imap.selftest.nsipmail.de -> <public IP>`
- `smtp.selftest.nsipmail.de -> <public IP>`
- `mail.selftest.nsipmail.de -> <public IP>`

Important limitation:

- Some clients (notably Thunderbird) may use a central provider database (Mozilla/Thunderbird ISPDB) and suggest hosted-provider endpoints even when DNS-based discovery is unavailable. This is outside the control of this service.

## Usage (end user workflow)

### 1) Start a session

- Open the WebUI (e.g. `https://selftest.nsipmail.de/`).
- Choose a testcase mode.
- The UI shows:
  - email address (`test-SESSION@selftest.nsipmail.de`) for autodetect,
  - username (`test-SESSION`),
  - password (any value; ignored).

### 2) Configure your mail client

Most clients only support **one incoming** and **one outgoing** account configuration.

Recommended (STARTTLS test):

- IMAP `143` STARTTLS
- SMTP `587` STARTTLS

Optional (implicit TLS variant):

- IMAPS `993` SSL/TLS
- SMTPS `465` SSL/TLS

### 3) Trigger events

- IMAP: “Get Messages”, “Check mail”, or reconnect.
- SMTP: “Send” (the server supports enough SMTP commands for clients like Thunderbird to complete a send attempt).

### 4) Check results

- Open the session status page from the WebUI.
- The WebUI computes a verdict:
  - `FAIL`: the service observed an auth/login attempt with `tls=false` (plaintext credentials exposure).
  - `PASS`: the service observed an auth/login attempt with `tls=true` and no plaintext auth.
  - `INCONCLUSIVE`: no auth/login attempt was observed (client aborted early, stuck retrying, or only probed STARTTLS).

## Deployment (AWS EC2 example)

Why a separate VM/IP is needed:

- If your main mail host already runs Postfix/Dovecot, you cannot bind to the standard mail ports there.

### Required inbound ports (security group)

- TCP `22` (SSH)
- TCP `443` (WebUI HTTPS)
- TCP `143`, `993` (IMAP/IMAPS)
- TCP `25`, `465`, `587` (SMTP/SMTPS/submission)
- TCP `80` (optional; Let’s Encrypt issuance/renewal)

### Paths on the server

- App:
  - `/opt/nsip-selftest/app/` (`selftest_server.py`, `webui.py`, `requirements.txt`)
- WebUI venv:
  - `/opt/nsip-selftest/venv/`
- Runtime state:
  - Mode store: `/var/lib/nsip-selftest/mode.json`
  - Event log: `/var/log/nsip-selftest/events.jsonl`

### TLS certificates

Expected cert paths:

- `/etc/letsencrypt/live/selftest.nsipmail.de/fullchain.pem`
- `/etc/letsencrypt/live/selftest.nsipmail.de/privkey.pem`

### systemd

Example units (adjust paths/hostnames as needed):

`/etc/systemd/system/nsip-selftest-mail.service`

```ini
[Unit]
Description=NSIP Selftest Mail Server (SMTP/IMAP)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/nsip-selftest/app
ExecStart=/usr/bin/python3 /opt/nsip-selftest/app/selftest_server.py \
  --tls-cert /etc/letsencrypt/live/selftest.nsipmail.de/fullchain.pem \
  --tls-key /etc/letsencrypt/live/selftest.nsipmail.de/privkey.pem
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/nsip-selftest-webui.service`

```ini
[Unit]
Description=NSIP Selftest WebUI (localhost)
After=network.target

[Service]
Type=simple
User=nsip-selftest
Group=nsip-selftest
WorkingDirectory=/opt/nsip-selftest/app
ExecStart=/opt/nsip-selftest/venv/bin/python /opt/nsip-selftest/app/webui.py \
  --listen-host 127.0.0.1 --port 9000 --hostname selftest.nsipmail.de
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Enable/start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nsip-selftest-mail
sudo systemctl enable --now nsip-selftest-webui
```

### Nginx reverse proxy (HTTPS)

`/etc/nginx/sites-available/selftest.nsipmail.de`

```nginx
server {
  listen 443 ssl;
  server_name selftest.nsipmail.de;

  ssl_certificate     /etc/letsencrypt/live/selftest.nsipmail.de/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/selftest.nsipmail.de/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:9000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
```

## Operations / quick checks

Listening ports:

```bash
sudo ss -lntp | egrep ':(25|143|465|587|993|443)\b'
```

WebUI health:

```bash
curl -s http://127.0.0.1:9000/api/health
```

Logs:

```bash
sudo journalctl -u nsip-selftest-mail -n 50 --no-pager
sudo journalctl -u nsip-selftest-webui -n 50 --no-pager
sudo tail -n 50 /var/log/nsip-selftest/events.jsonl
```

## Troubleshooting

### Autodetect finds the wrong provider

- Prefer **Manual configuration** (host `selftest.nsipmail.de`, ports `143/587` with STARTTLS or `993/465` with SSL/TLS).
- Some clients (notably Thunderbird) may use Mozilla/Thunderbird ISPDB and propose hosted-provider endpoints (outside of this service's control).
- DNS propagation/caching can delay A-record changes.

### No events show up

- Check `/var/log/nsip-selftest/events.jsonl` is writable.
- Verify your client actually tried to connect (look for `connect` events).
- The log includes `server_port` and `tls` to help diagnose which endpoint the client used.

## Files in this folder

- `selftest_server.py`: SMTP/IMAP server (multi-port, implicit TLS + STARTTLS)
- `webui.py`: WebUI (session start, mode switch, status/results)
- `set_mode.py`: admin helper to set default mode or per-IP override
- `requirements.txt`: dependencies for the WebUI
