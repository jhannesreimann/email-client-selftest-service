# Thunderbird – Kali Linux – T1 (STARTTLS Stripping)

**Client:** Mozilla Thunderbird 140.4.0esr  
**OS:** Kali GNU/Linux Rolling (x86_64), Linux 6.12.27-amd64  
**Hardware:** Lenovo Legion 5 15ACH6H

## 1. Test Setup

- **Account:** `testuser@nsipmail.de`
- **Server:** `mail.nsipmail.de` (`13.62.95.49`)
- **Proxy:** mitmproxy/mitmdump 11.1.3 on Kali
- **Mode:** `--mode socks5` (SOCKS5 proxy on localhost:1080)
- **Thunderbird proxy settings:**
  - SOCKS v5: `127.0.0.1`, Port `1080`
  - Proxy DNS via SOCKS enabled

### 1.1 IMAP Configuration (Test)

- **Protocol:** IMAP
- **Hostname:** `mail.nsipmail.de`
- **Port:** `143`
- **Connection security:** `STARTTLS`
- **Authentication:** "Normal password"

### 1.2 SMTP Configuration (Test)

- **Protocol:** SMTP (Submission)
- **Hostname:** `mail.nsipmail.de`
- **Port:** `587`
- **Connection security:** `STARTTLS`
- **Authentication:** "Normal password"

---

## 2. IMAP – T1 (STARTTLS Stripping)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s imap/t1.py
```

**Script behavior:**
- `imap/t1.py` removes the `STARTTLS` capability from the server's IMAP greeting/capability response.

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:143
starttls in position 75
client sends starttls
...
unserializable object: bytearray(b'BAD Error in IMAP command received by server.\r\n')
```

**Thunderbird behavior:**
- Connection spinner keeps running / connection eventually fails.
- No successful login is completed.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/imap_t1.mitm`.
- Checked with:
  ```bash
  strings /tmp/imap_t1.mitm | grep -i "LOGIN"
  strings /tmp/imap_t1.mitm | grep -i "AUTH"
  ```
- **Result:** No occurrences of `LOGIN testuser ...` or similar, no visible plaintext credentials.

**Conclusion (IMAP/T1):**
- Thunderbird attempts STARTTLS, but when the handshake/capability is broken by the attacker, it does **not** fall back to an unencrypted login.
- Instead, the connection fails.
- **Assessment:** Thunderbird **not vulnerable** to IMAP T1 (STARTTLS stripping) in this configuration.

---

## 3. SMTP – T1 (STARTTLS Stripping)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s smtp/t1.py
```

**Script behavior:**
- `smtp/t1.py` removes `250-STARTTLS` from the SMTP `EHLO` response, so the server no longer advertises STARTTLS.

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:587
starttls in position 81
... (no AUTH in cleartext)
```

**Thunderbird behavior (user-visible error message):**
> Sending of the message failed.  
> An error occurred while sending mail: **Unable to establish a secure link with Outgoing server (SMTP) mail.nsipmail.de using STARTTLS since it doesn't advertise that feature. Switch off STARTTLS for that server or contact your service provider.**

**Interpretation:**
- Thunderbird expects STARTTLS (because of the account configuration).
- When the server (manipulated by mitmproxy) does not advertise STARTTLS anymore, Thunderbird:
  - **Aborts** the SMTP session.
  - Does **not** send any SMTP `AUTH` with credentials in plaintext.
  - Explicitly suggests to the user to **switch off STARTTLS**.

**Security assessment:**
- Technically: No credential exposure in this scenario.
- From a usability/security perspective:
  - The suggested action ("Switch off STARTTLS") would be a **conscious user misconfiguration** that _could_ make future connections insecure.
  - In the tested configuration, as long as the user does **not** switch off STARTTLS, Thunderbird remains **not vulnerable** to SMTP T1.

---

## 4. Summary of T1 Findings for Thunderbird (Kali)

| Protocol | Port | Test | Result | Vulnerable? |
|----------|------|------|--------|-------------|
| IMAP     | 143  | T1   | Connection fails, no plaintext `LOGIN`, no credentials observed | **No** |
| SMTP     | 587  | T1   | Error message about missing STARTTLS, no plaintext `AUTH`, user is asked to disable STARTTLS | **No*** |

`*` **Note:** Security still depends on user behavior. If a user follows the suggestion and disables STARTTLS, subsequent connections could be downgraded. This is considered a user-induced misconfiguration, not a silent downgrade.

---

## 5. Planned / Remaining Tests

To fully evaluate Thunderbird against the NDSS 2025 test matrix, the following tests are still open:

### 5.1 IMAP / POP3 Tests
- **IMAP T2:** ServerHello replacement during TLS negotiation
- **IMAP T3:** STARTTLS command rejection
- **IMAP T4:** Post-handshake disruption
- **POP3 T1–T4:** Same four tests on port 110 (STARTTLS) for POP3

### 5.2 SMTP Tests
- **SMTP T2:** ServerHello replacement during TLS negotiation
- **SMTP T3:** STARTTLS command rejection
- **SMTP T4:** Post-handshake disruption

### 5.3 Certificate Validation (C1–C4)
- C1: Self-signed certificate
- C2: Expired certificate
- C3: Wrong chain / intermediate
- C4: Domain mismatch

For each combination (protocol × test case), we plan to document:
- Exact test setup (ports, security settings, scripts)
- mitmdump/mitmproxy logs (sanitized)
- Thunderbird UI behavior (prompts, warnings, error messages)
- Security assessment: plaintext credentials? downgrade? user interaction required?
