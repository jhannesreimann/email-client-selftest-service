# MITM Attack Scripts

This directory contains the original research scripts from the NDSS 2025 paper authors.

## 📂 Structure

### `email-security/` 
**Source:** https://github.com/tls-downgrade/email-security

Protocol-specific test cases implementing the four attack scenarios for security downgrade (T1-T4) for SMTP, IMAP, and POP3.

**Test Cases:**
- **T1:** STARTTLS capability stripping
- **T2:** ServerHello replacement during TLS negotiation
- **T3:** STARTTLS command rejection
- **T4:** Post-handshake session disruption

### `tls-downgrade/`
**Source:** https://github.com/tls-downgrade/tls-downgrade

TLS version downgrade proof-of-concept that forces clients to use older, potentially vulnerable TLS versions.

**Files:**
```
tls-downgrade/
├── downgrade_poc.py   # Main downgrade attack logic
├── client_hello.py    # TLS ClientHello parser
├── proxy.py           # Transparent proxy configuration
└── next_layer.py      # Layer handling (shared)
```

---

## 🚀 Usage

### Email Protocol Test Cases (T1-T4)

```bash
# Navigate to email-security directory
cd 50-implementation/mitm-scripts/email-security/

# Setup mitmproxy (one-time)
cp -r smtp/ imap/ pop3/ <mitmproxy-installation>/
cp next_layer.py <mitmproxy-installation>/addons/

# Run specific test case
mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost -s smtp/t1.py

# Or for IMAP
mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost -s imap/t1.py
```

### TLS Version Downgrade

```bash
# Navigate to tls-downgrade directory
cd 50-implementation/mitm-scripts/tls-downgrade/

# Setup mitmproxy (one-time)
cp *.py <mitmproxy-installation>/
cp next_layer.py <mitmproxy-installation>/addons/

# Run downgrade attack
mitmproxy -s downgrade_poc.py
```

---

## 🔍 Script Analysis

### Summary: T1-T4 – What They Do Per Protocol

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    ATTACK SCRIPTS (T1-T4)                                       │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────┬──────────────────────────────────┬────────────────────────────┐
│           IMAP                   │           SMTP                   │           POP3             │
│     (imap/t1.py - t4.py)         │     (smtp/t1.py - t4.py)         │    (pop3/t1.py - t4.py)    │
├──────────────────────────────────┼──────────────────────────────────┼────────────────────────────┤
│                                  │                                  │                            │
│ Port 993 (IMAPS):                │ Port 465 (SMTPS):                │ Port 995 (POP3S):          │
│ → Block (empty response)         │ → Block (empty response)         │ → Block (empty response)   │
│   Forces fallback to 143         │   Forces fallback to 587         │   Forces fallback to 110   │
│                                  │                                  │                            │
│ Port 143 (IMAP):                 │ Port 587 (Submission):           │ Port 110 (POP3):           │
│ ─────────────────                │ ──────────────────────           │ ────────────────           │
│                                  │                                  │                            │
│ T1: Strip STARTTLS from          │ T1: Strip STARTTLS from          │ T1: Strip STLS from        │
│     CAPABILITY response          │     EHLO response                │     CAPA response          │
│                                  │                                  │                            │
│ T2: Replace TLS ServerHello      │ T2: Replace TLS ServerHello      │ T2: Replace TLS ServerHello│
│     with error after ClientHello │     with error after ClientHello │     with error             │
│                                  │                                  │                            │
│ T3: Reject STARTTLS command      │ T3: Reject STARTTLS command      │ T3: Reject STLS command    │
│     with "BAD" response          │     with error response          │     with "-ERR" response   │
│                                  │                                  │                            │
│ T4: Replace TLS Application Data │ T4: Replace TLS Application Data │ T4: Replace TLS App Data   │
│     with plaintext NOOP          │     with plaintext               │     with "-ERR"            │
│                                  │                                  │                            │
└──────────────────────────────────┴──────────────────────────────────┴────────────────────────────┘
```

### Detailed example: T1-T4 for SMTP
#### T1: STARTTLS Stripping (smtp/t1.py)

**Attack Vector:** Removes `STARTTLS` capability from server's EHLO response

**Key Code:**
```python
if b'STARTTLS' in server_msg:
    position = server_msg.find(b'250-STARTTLS')
    # Remove the STARTTLS announcement
    server_msg[position:position+14] = b''
    msg.content = server_msg
```

**Result:** Client believes server doesn't support STARTTLS, falls back to plaintext

---

#### T2: ServerHello Replacement (smtp/t2.py)

**Attack Vector:** Intercepts TLS negotiation, replaces ServerHello with error message

**Result:** Client abandons TLS upgrade attempt

---

#### T3: STARTTLS Rejection (smtp/t3.py)

**Attack Vector:** Responds with error when client sends STARTTLS command

**Key Code:**
```python
if b'220 2.0.0 Ready to start TLS' in server_msg:
    server_msg[0:] = b'502 5.5.2 Error: command not recognized\r\n'
    msg.content = server_msg
```

**Result:** Tests if client proceeds with plaintext after STARTTLS rejection

---

#### T4: Post-Handshake Disruption (smtp/t4.py)

**Attack Vector:** Disrupts TLS session after successful handshake by injecting commands

**Result:** Tests session resilience and client fallback behavior

---

### TLS Downgrade (downgrade_poc.py)

**Attack Vector:** Forces client to downgrade from TLS 1.3 → TLS 1.2 → older versions

**Key Features:**
- Parses ClientHello to detect supported TLS versions
- Manipulates TLS handshake to force downgrade
- Logs downgrade attempts and results

**Code Flow:**
1. Intercept ClientHello (0x16 message type, 0x01 handshake)
2. Parse supported TLS versions from extensions
3. Force older version by manipulating ServerHello
4. Log results for analysis

---

## ⚠️ Important Notes

1. **Transparent Mode:** Requires root/sudo for port binding and iptables configuration
2. **CA Certificate:** Clients must trust mitmproxy's CA cert for HTTPS interception
3. **Network Routing:** Configure test device to route all traffic through mitmproxy
4. **Port Blocking:** For auto-detect testing, may need to block secure ports (993, 465, 995)

### Manual vs. Autodetect Client Configuration

| Aspect | Manual Configuration | Autodetect |
|--------|---------------------|------------|
| **User sets** | Port + Security explicitly (e.g., 143 + STARTTLS) | Only email address |
| **Client decides** | Nothing – user controls everything | Port, security, authentication |
| **Attack surface** | Only the chosen port | All ports (993 → 143 fallback) |
| **What we test** | Does client fall back to plaintext? | Does client choose insecure option? |

### Attack Flow Diagrams

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                         ATTACK FLOWS                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

AUTODETECT SCENARIO (Example: IMAP):
====================================

   LOCAL MACHINE                                                          MAIL SERVER
   ─────────────                                                          ───────────
   Email Client              mitmproxy (MITM)                             mail.nsipmail.de
        │                          │                                            │
        │──── Connect :993 ───────►│                                            │
        │                          │──── Connect :993 ─────────────────────────►│
        │                          │◄─── TLS ServerHello ───────────────────────│
        │◄─── [BLOCKED/EMPTY] ─────│  (Script blocks implicit TLS)              │
        │                          │                                            │
        │  (Client: "993 failed, try 143...")                                   │
        │                          │                                            │
        │──── Connect :143 ───────►│                                            │
        │                          │──── Connect :143 ─────────────────────────►│
        │                          │◄─── * OK ... CAPABILITY ... STARTTLS ──────│
        │◄─── * OK ... CAPABILITY ─│  (T1: STARTTLS stripped from response)     │
        │     [STARTTLS removed]   │                                            │
        │                          │                                            │
        │  (Client: "No STARTTLS available, server doesn't support TLS")        │
        │                          │                                            │
        │──── a1 LOGIN user pass ─►│                                            │
        │              ▲           │                                            │
        │              │           │                                            │
        │     CREDENTIALS IN       │                                            │
        │     PLAINTEXT!           │                                            │


MANUAL CONFIG SCENARIO (Example: SMTP Port 587):
================================================

   LOCAL MACHINE                                                          MAIL SERVER
   ─────────────                                                          ───────────
   Email Client              mitmproxy (MITM)                             mail.nsipmail.de
        │                          │                                            │
        │──── Connect :587 ───────►│                                            │
        │                          │──── Connect :587 ─────────────────────────►│
        │                          │◄─── 220 mail.nsipmail.de ESMTP ────────────│
        │◄─── 220 ... ESMTP ───────│                                            │
        │                          │                                            │
        │──── EHLO client ────────►│                                            │
        │                          │──── EHLO client ──────────────────────────►│
        │                          │◄─── 250-STARTTLS ... ──────────────────────│
        │◄─── 250-... [stripped] ──│  (T1: STARTTLS removed from EHLO response) │
        │                          │                                            │
        │                          │                                            │
        │  SECURE CLIENT (Thunderbird):                                         │
        │  "STARTTLS required but not offered → Connection aborted"             │
        │                          │                                            │
        │  INSECURE CLIENT:                                                     │
        │  "OK, continue without TLS"                                           │
        │──── AUTH PLAIN base64 ──►│  ← CREDENTIALS EXPOSED!                    │
```
