# MITM Attack Scripts

This directory contains the original research scripts from the NDSS 2025 paper authors.

## 📂 Structure

### `email-security/` 
**Source:** https://github.com/tls-downgrade/email-security

Protocol-specific test cases implementing the four attack scenarios (T1-T4) for SMTP, IMAP, and POP3.

**Test Cases:**
- **T1:** STARTTLS capability stripping
- **T2:** ServerHello replacement during TLS negotiation
- **T3:** STARTTLS command rejection
- **T4:** Post-handshake session disruption

**Files:**
```
email-security/
├── smtp/
│   ├── t1.py    # Strips STARTTLS from EHLO response
│   ├── t2.py    # Replaces ServerHello with error
│   ├── t3.py    # Rejects STARTTLS command
│   └── t4.py    # Disrupts TLS session after handshake
├── imap/
│   ├── t1.py    # IMAP-specific T1 implementation
│   ├── t2.py    # IMAP-specific T2 implementation
│   ├── t3.py    # IMAP-specific T3 implementation
│   └── t4.py    # IMAP-specific T4 implementation
├── pop3/
│   ├── t1.py    # POP3-specific T1 implementation
│   ├── t2.py    # POP3-specific T2 implementation
│   ├── t3.py    # POP3-specific T3 implementation
│   └── t4.py    # POP3-specific T4 implementation
└── next_layer.py   # mitmproxy layer modification
```

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

### T1: STARTTLS Stripping (smtp/t1.py)

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

### T2: ServerHello Replacement (smtp/t2.py)

**Attack Vector:** Intercepts TLS negotiation, replaces ServerHello with error message

**Result:** Client abandons TLS upgrade attempt

---

### T3: STARTTLS Rejection (smtp/t3.py)

**Attack Vector:** Responds with error when client sends STARTTLS command

**Key Code:**
```python
if b'220 2.0.0 Ready to start TLS' in server_msg:
    server_msg[0:] = b'502 5.5.2 Error: command not recognized\r\n'
    msg.content = server_msg
```

**Result:** Tests if client proceeds with plaintext after STARTTLS rejection

---

### T4: Post-Handshake Disruption (smtp/t4.py)

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

## 📋 Testing Checklist

For each email client tested:

- [ ] Run T1 (STARTTLS stripping) on SMTP port 587
- [ ] Run T1 on IMAP port 143
- [ ] Run T2 (ServerHello replacement) on both protocols
- [ ] Run T3 (STARTTLS rejection) on both protocols
- [ ] Run T4 (Post-handshake disruption) on both protocols
- [ ] Document: Does client send plaintext credentials?
- [ ] Document: Does client show security warning?
- [ ] Save logs and notes to `60-findings/`

---

## ⚠️ Important Notes

1. **Transparent Mode:** Requires root/sudo for port binding and iptables configuration
2. **CA Certificate:** Clients must trust mitmproxy's CA cert for HTTPS interception
3. **Network Routing:** Configure test device to route all traffic through mitmproxy
4. **Port Blocking:** For auto-detect testing, may need to block secure ports (993, 465, 995)

---

*Scripts sourced from NDSS 2025 paper authors' GitHub repositories*
