# email-client-selftest-service

A university project from the HPI seminar Network Security in Practice (NSIP), winter term 2025/26, supervised by Feng and Pejman. Built by Team 2: Sofya and Jhannes.

**Status:** coursework, finished in March 2026 and no longer maintained. The public demo instance at `selftest.nsipmail.de` was shut down after the course ended. Everything here still works if you host it yourself.

## Why this exists

Most mail clients try to guess account settings automatically. You enter an email address and a password, the client probes candidate servers and connects with STARTTLS or implicit TLS, depending on what each server claims to offer. An attacker on the same network can interfere with that negotiation: strip STARTTLS from the capability list, accept the command and then drop the connection, reject it outright, or break the session right after the handshake. What happens next depends on the client. A careful one aborts and warns you. A careless one falls back to plaintext authentication and hands your password to whoever is listening.

That is roughly the setup of the NDSS 2025 paper [A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems](https://dx.doi.org/10.14722/ndss.2025.240532). We spent a semester recreating parts of that work and building our own tooling on top of it.

## What we built

Two tools came out of this, plus a pile of lab infrastructure.

### Selftest service (`50-implementation/selftest-service`)

The main deliverable. The paper's methodology needs a man-in-the-middle proxy between client and server, which is not something you can ask an ordinary user to install. So we turned the setup around. Instead of attacking the connection, we run a deliberately misbehaving mail server and let people point their own clients at it. No proxy, no certificates to import.

It has two parts:

- `selftest_server.py`, written against the Python standard library only. Minimal SMTP and IMAP endpoints on the standard mail ports (25, 143, 465, 587, 993) that can act in five ways: a normal `baseline`, plus four disruption patterns matching the paper's test cases T1-T4. In test modes it also refuses the implicit TLS ports, so clients fall back to the STARTTLS ports where the interesting decisions happen.
- `webui.py`, a small FastAPI app. Start a session in the browser, get credentials like `test-a1b2c3@<domain>`, configure your mail client with them, trigger a send or receive, and watch what your client actually did. Sessions are derived from the username and stored per public IP with a TTL.

Each step ends in a verdict: PASS means authentication happened inside TLS, FAIL means your client authenticated without TLS, INCONCLUSIVE means no auth attempt was observed, WARN means the client noticed something and asked you what to do. Events are logged without passwords.

### Server checker (`50-implementation/server-checker`)

A single Bash script for mail server admins. It reads the active Postfix and Dovecot configuration via `postconf` and `doveconf` and reports settings that make downgrade attacks possible, such as `smtpd_tls_security_level = may` or Dovecot's `disable_plaintext_auth = no`. Every finding comes with the recommended fix. Output is human readable by default, JSON with `-o`.

### Lab infrastructure and research material

- `50-implementation/mitm-scripts/` contains the original attack scripts from the paper authors ([email-security](https://github.com/tls-downgrade/email-security), [tls-downgrade](https://github.com/tls-downgrade/tls-downgrade)), vendored with light modifications.
- `50-implementation/server-setup/` documents the deliberately vulnerable Postfix/Dovecot target we ran on AWS during the course, down to the exact settings that made plaintext auth possible.
- `50-implementation/test-setup/` has network namespace and iptables scripts that routed a local Thunderbird through mitmproxy transparently.
- `60-findings/` holds results: a per-client vulnerability matrix and a passive Shodan measurement of how common risky server configurations look from the outside.
- `00-deliverables/` through `40-references/` is course paperwork: slides, the final report, meeting protocols, planning notes and paper summaries.

## Running the selftest service locally

Linux with root access (ports below 1024 need privileges) and Python 3.10 or newer.

```bash
cd 50-implementation/selftest-service
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# throwaway certificate, fine for local poking around;
# real clients will not trust it without extra convincing
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"

# terminal 1: the mail server (root because of the default ports)
sudo .venv/bin/python selftest_server.py \
  --tls-cert cert.pem --tls-key key.pem \
  --mode-store /tmp/selftest/mode.json \
  --log /tmp/selftest/events.jsonl

# terminal 2: the web UI
.venv/bin/python webui.py \
  --store /tmp/selftest/mode.json \
  --events /tmp/selftest/events.jsonl
```

Open http://127.0.0.1:9000, start a session, and configure any mail client with the credentials shown. Thunderbird is what we tested with.

For anything beyond local poking you want a VM with public DNS records and a real certificate, because client behavior differs depending on what they trust. The full self-hosting walkthrough, including systemd units and nginx config, is in the [selftest service README](50-implementation/selftest-service/README.md).

### Server checker

Run it on a machine with Postfix and/or Dovecot installed:

```bash
cd 50-implementation/server-checker
chmod +x server-checker-for-admin.sh
sudo ./server-checker-for-admin.sh              # report in the terminal
sudo ./server-checker-for-admin.sh -o out.json  # JSON instead
```

On a hardened server it finds nothing. On our deliberately vulnerable target it flagged every hole we had drilled.

## What we found

Short version: Thunderbird 140 ESR on Linux held up well under manual configuration. Across the four disruption patterns on IMAP, SMTP and POP3, most combinations were handled safely. Two cases landed on "user dependent": Thunderbird notices that something is wrong and warns, but suggests actions like turning off security settings that would leak credentials if the user follows them. Logs and details are in `60-findings/client/`.

The Shodan side asked how often internet-facing mail servers advertise AUTH before TLS is established. Under one query profile, roughly half of the observed submission services on port 587 did. Banner-based heuristics prove nothing on their own, but the numbers suggest the server-side misconfiguration this project relies on is far from exotic. Plots and reproduction scripts are in `60-findings/server/shodan-plots/`.

## Known limitations

- The session override in the WebUI is stored per public IP, so two people behind the same NAT cannot test at the same time.
- We only tested Thunderbird on Linux in depth. The other rows of the matrix were never filled in.
- The service simulates a misbehaving server instead of intercepting traffic, so its T1-T4 modes approximate the paper's scenarios rather than reproducing them exactly. Design notes on that are in `50-implementation/selftest-service/PAPER_PARITY_AND_NEXT_STEPS.md`.
- POP3 support exists in the vendored scripts but was deprioritized early on.
- Nothing here is maintained. If you break it, you get to keep both halves.

## Repository layout

| Directory | Contents |
|---|---|
| `00-deliverables/` | Slides and the final report submitted for grading |
| `10-planning/` | Project plans, progress tracking, design sketches |
| `20-protocol/` | Weekly supervisor meeting notes |
| `30-summary/` | Summaries of related papers |
| `40-references/` | The literature itself |
| `50-implementation/` | Both tools, lab documentation, vendored attack scripts |
| `60-findings/` | Test results and measurements |

## License

MIT, see [LICENSE](LICENSE).
