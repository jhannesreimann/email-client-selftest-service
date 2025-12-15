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

## 3. IMAP – T2 (ServerHello Replacement / STARTTLS Error)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s imap/t2.py
```

**Script behavior:**
- `imap/t2.py` manipulates the TLS negotiation phase and rejects STARTTLS after the client has already sent a TLS ClientHello.

**Observed mitmdump log (excerpt):**
```text
client sends starttls
bytearray(b'20 OK Begin TLS negotiation now.\r\n')
...
reject the STARTTLS after clienthello
bytearray(b'BAD Error in IMAP command received by server.\r\n')
```

**Thunderbird behavior:**
- Connection remains in a loading state and eventually fails.
- No UI error dialog was observed during this test.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/imap_t2.mitm`.
- Checked with:
  ```bash
  strings /tmp/imap_t2.mitm | grep -i "LOGIN"
  strings /tmp/imap_t2.mitm | grep -i "AUTH"
  ```
- **Result:** No occurrences of `LOGIN testuser ...` or similar, no visible plaintext credentials.

**Conclusion (IMAP/T2):**
- Thunderbird does **not** fall back to plaintext authentication when the TLS negotiation is actively broken.
- The connection simply fails without exposing credentials.
- **Assessment:** Thunderbird **not vulnerable** to IMAP T2 in this configuration.

---

## 4. IMAP – T3 (STARTTLS Command Rejection)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s imap/t3.py -w /tmp/imap_t3.mitm
```

**Script behavior:**
- `imap/t3.py` replaces the server's `OK Begin TLS negotiation now` response with:
  ```text
  BAD Error in IMAP command received by server.
  ```
  directly after the client sends the `STARTTLS` command.

**Observed mitmdump log (excerpt):**
```text
client sends starttls
b'BAD Error in IMAP command received by server.\r\n'
```

**Thunderbird behavior:**
- Connection remains stuck in a loading state and eventually fails.
- No successful mailbox listing or message fetch is observed.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/imap_t3.mitm`.
- Checked with:
  ```bash
  strings /tmp/imap_t3.mitm | grep -i "LOGIN"
  strings /tmp/imap_t3.mitm | grep -i "AUTH"
  ```
- **Result:** Only server capability lines like
  `* OK [CAPABILITY IMAP4rev1 ... STARTTLS AUTH=PLAIN AUTH=LOGIN]` appear.
  No `LOGIN testuser ...` or password strings are present.

**Conclusion (IMAP/T3):**
- Even when the server explicitly rejects `STARTTLS`, Thunderbird does **not** send plaintext credentials.
- The connection fails instead of falling back to an unencrypted IMAP session.
- **Assessment:** Thunderbird **not vulnerable** to IMAP T3 in this configuration.

---

## 5. IMAP – T4 (Post-Handshake / MITM Certificate Injection)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s imap/t4.py -w /tmp/imap_t4.mitm
```

**Script behavior:**
- `imap/t4.py` allows the STARTTLS handshake to proceed, but mitmproxy intercepts the TLS connection and presents its own (untrusted) certificate instead of the server's legitimate Let's Encrypt certificate.

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:143
...
bytearray(b'A NOOP\r\n')
...
client disconnect
```

**Thunderbird behavior (user-visible warning):**
> The certificate for mail.nsipmail.de does not come from a trusted source.

When clicking "More Information":
- Dialog shows: `Location: mail.nsipmail.de:143`
- Warning: "This site attempts to identify itself with invalid information."
- Options: **"Confirm Security Exception"** or **"Cancel"**

**Security assessment:**
- Thunderbird **detects** the invalid/untrusted certificate.
- It does **not** automatically proceed or send credentials.
- The user must **actively click "Confirm Security Exception"** to bypass the warning.
- If the user clicks "Cancel", no credentials are exposed.

**Conclusion (IMAP/T4):**
- Thunderbird's certificate validation is working correctly.
- The attack is detected and flagged to the user.
- However, the user *can* choose to ignore the warning and add an exception.
- **Assessment:** ⚠️ **User-Dependent** – technically secure unless user actively bypasses the warning.

---

## 6. SMTP – T1 (STARTTLS Stripping)

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

## 7. SMTP – T2 (ServerHello Replacement / TLS Unavailable)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s smtp/t2.py -w /tmp/smtp_t2.mitm
```

**Script behavior:**
- `smtp/t2.py` replaces the server's TLS negotiation response with:
  ```text
  454 TLS not available due to temporary reason
  ```

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:587
...
bytearray(b'454 TLS not available due to temporary reason\r\n')
...
client disconnect
```

**Thunderbird behavior (user-visible error message):**
> Sending of the message failed.  
> The message could not be sent because the connection to Outgoing server (SMTP) mail.nsipmail.de timed out. Try again.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/smtp_t2.mitm`.
- Checked with:
  ```bash
  strings /tmp/smtp_t2.mitm | grep -i "AUTH"
  ```
- **Result:** No `AUTH PLAIN` or `AUTH LOGIN` commands with credentials found.

**Conclusion (SMTP/T2):**
- Thunderbird waits for TLS to succeed, but the manipulated response causes a timeout.
- The client does **not** fall back to plaintext authentication.
- **Assessment:** Thunderbird **not vulnerable** to SMTP T2 in this configuration.

---

## 8. SMTP – T3 (STARTTLS Command Rejection)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s smtp/t3.py -w /tmp/smtp_t3.mitm
```

**Script behavior:**
- `smtp/t3.py` intercepts the client's `STARTTLS` command and responds with:
  ```text
  454 TLS not available due to temporary reason
  ```

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:587
...
client sends starttls
bytearray(b'454 TLS not available due to temporary reason\r\n')
...
client disconnect
```

**Thunderbird behavior (user-visible error message):**
> Sending of the message failed.  
> An error occurred while sending mail: Outgoing server (SMTP) error. The server responded: TLS not available due to temporary reason.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/smtp_t3.mitm`.
- Checked with:
  ```bash
  strings /tmp/smtp_t3.mitm | grep -i "AUTH"
  ```
- **Result:** No `AUTH PLAIN` or `AUTH LOGIN` commands with credentials found.

**Conclusion (SMTP/T3):**
- Thunderbird receives the TLS rejection and immediately aborts.
- The client does **not** fall back to plaintext authentication.
- **Assessment:** Thunderbird **not vulnerable** to SMTP T3 in this configuration.

---

## 9. SMTP – T4 (Post-Handshake Disruption)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s smtp/t4.py -w /tmp/smtp_t4.mitm
```

**Script behavior:**
- `smtp/t4.py` attempts to disrupt the TLS handshake after STARTTLS is initiated.
- Multiple "Substring not found" messages indicate the script couldn't find expected patterns.
- Eventually injects:
  ```text
  454 TLS not available due to temporary reason
  ```

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:587
Substring not found
...
bytearray(b'454 TLS not available due to temporary reason\r\n')
Substring not found
...
client disconnect
```

**Thunderbird behavior (user-visible error message):**
> Sending of the message failed.  
> The message could not be sent because the connection to Outgoing server (SMTP) mail.nsipmail.de timed out. Try again.

**Verification of plaintext credentials:**
- Traffic dump written via `-w /tmp/smtp_t4.mitm`.
- Checked with:
  ```bash
  strings /tmp/smtp_t4.mitm | grep -i "AUTH"
  ```
- **Result:** No `AUTH PLAIN` or `AUTH LOGIN` commands with credentials found.

**Comparison with IMAP T4:**
- IMAP T4 showed a certificate warning (mitmproxy CA presented).
- SMTP T4 does **not** show a certificate warning – instead, the connection times out.
- This may be due to differences in how the script handles SMTP vs IMAP, or Thunderbird's SMTP implementation rejecting the manipulated handshake earlier.

**Conclusion (SMTP/T4):**
- Thunderbird does **not** fall back to plaintext authentication.
- The connection times out without exposing credentials.
- **Assessment:** Thunderbird **not vulnerable** to SMTP T4 in this configuration.

---

## 10. POP3 – T1 (STARTTLS Stripping)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s pop3/t1.py
```

**Script behavior:**
- `pop3/t1.py` removes `STLS` from the POP3 CAPA response, so the server no longer advertises STARTTLS.

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:110
starttls in position 62
...
bytearray(b'+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nAUTH-RESP-CODE\r\nUSER\r\nSASL PLAIN LOGIN\r\n.\r\n')
...
client disconnect
```

**Thunderbird behavior (user-visible error message):**
> Unable to establish TLS connection to POP3 server. The server may be down or may be incorrectly configured. Please verify the correct configuration in the Server Settings for your mail server in the Account Settings window and try again.

**Verification of plaintext credentials:**
- No `USER` or `PASS` commands with credentials observed in the log.

**Conclusion (POP3/T1):**
- Thunderbird expects STARTTLS but the capability is stripped by the attacker.
- The client does **not** fall back to plaintext authentication.
- **Assessment:** Thunderbird **not vulnerable** to POP3 T1 in this configuration.

---

## 11. POP3 – T2 (ServerHello Replacement / STARTTLS Rejection after ClientHello)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s pop3/t2.py
```

**Script behavior:**
- `pop3/t2.py` allows the client to send `STLS`, then rejects the TLS handshake after the ClientHello with:
  ```text
  -ERR Command not recognised
  ```

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:110
...
client sends starttls
...
reject the STARTTLS after clienthello
bytearray(b'-ERR Command not recognised\r\n')
...
client disconnect
```

**Thunderbird behavior:**
- No visible error message displayed.
- Connection silently fails (no mailbox update).
- Thunderbird retries in background but does not fall back to plaintext.

**Verification of plaintext credentials:**
- No `USER` or `PASS` commands with credentials observed in the log.

**Conclusion (POP3/T2):**
- Thunderbird does **not** fall back to plaintext authentication when TLS is rejected mid-handshake.
- **Assessment:** Thunderbird **not vulnerable** to POP3 T2 in this configuration.

---

## 12. POP3 – T3 (STARTTLS Command Rejection)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s pop3/t3.py
```

**Script behavior:**
- `pop3/t3.py` rejects the STARTTLS command with:
  ```text
  -ERR Command not recognised
  ```

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:110
...
reject the STARTTLS after clienthello
bytearray(b'-ERR Command not recognised\r\n')
...
client disconnect
```

**Thunderbird behavior:**
- No visible error message displayed.
- Loading indicator appears briefly, then stops.
- Connection silently fails without falling back to plaintext.

**Verification of plaintext credentials:**
- No `USER` or `PASS` commands with credentials observed in the log.

**Conclusion (POP3/T3):**
- Thunderbird does **not** fall back to plaintext authentication when STARTTLS is rejected.
- **Assessment:** Thunderbird **not vulnerable** to POP3 T3 in this configuration.

---

## 13. POP3 – T4 (Post-Handshake Disruption)

**mitmdump command:**
```bash
mitmdump --mode socks5 -s pop3/t4.py
```

**Script behavior:**
- `pop3/t4.py` attempts to disrupt the connection after STARTTLS handshake.
- Injects `-ERR` response to terminate the session.

**Observed mitmdump log (excerpt):**
```text
server connect mail.nsipmail.de:110
...
bytearray(b'-ERR\r\n')
...
client disconnect
```

**Thunderbird behavior:**
- No visible error message displayed.
- Loading indicator appears briefly, then stops.
- Connection silently fails without falling back to plaintext.
- No certificate warning (unlike IMAP T4).

**Verification of plaintext credentials:**
- No `USER` or `PASS` commands with credentials observed in the log.

**Conclusion (POP3/T4):**
- Thunderbird does **not** fall back to plaintext authentication.
- The connection fails silently without exposing credentials.
- **Assessment:** Thunderbird **not vulnerable** to POP3 T4 in this configuration.

---

## 14. Summary of Findings for Thunderbird (Kali)

| Protocol | Port | Test | Result | Vulnerable? |
|----------|------|------|--------|-------------|
| IMAP     | 143  | T1   | Connection fails, no plaintext `LOGIN`, no credentials observed | **No** |
| IMAP     | 143  | T2   | Connection fails after manipulated TLS negotiation, no plaintext `LOGIN` | **No** |
| IMAP     | 143  | T3   | STARTTLS rejected, connection fails, only capability lines with AUTH=PLAIN/LOGIN | **No** |
| IMAP     | 143  | T4   | Certificate warning shown, user must confirm exception to proceed | **No*** |
| SMTP     | 587  | T1   | Error message about missing STARTTLS, no plaintext `AUTH`, user is asked to disable STARTTLS | **No*** |
| SMTP     | 587  | T2   | TLS unavailable error, connection times out, no plaintext `AUTH` | **No** |
| SMTP     | 587  | T3   | STARTTLS rejected, error shown, no plaintext `AUTH` | **No** |
| SMTP     | 587  | T4   | Connection times out, no plaintext `AUTH` | **No** |
| POP3     | 110  | T1   | TLS connection error, no plaintext `USER`/`PASS` | **No** |
| POP3     | 110  | T2   | Connection silently fails, no plaintext `USER`/`PASS` | **No** |
| POP3     | 110  | T3   | Connection silently fails, no plaintext `USER`/`PASS` | **No** |
| POP3     | 110  | T4   | Connection silently fails, no plaintext `USER`/`PASS` | **No** |

`*` **Note:** Security depends on user behavior. For IMAP T4, the user must actively click "Confirm Security Exception" to bypass certificate validation. For SMTP T1, the user must manually disable STARTTLS. Both are considered user-induced misconfigurations, not silent downgrades.

---

## 15. Planned / Remaining Tests

### 15.1 Certificate Validation (C1–C4)
- C1: Self-signed certificate
- C2: Expired certificate
- C3: Wrong chain / intermediate
- C4: Domain mismatch

For each combination (protocol × test case), we plan to document:
- Exact test setup (ports, security settings, scripts)
- mitmdump/mitmproxy logs (sanitized)
- Thunderbird UI behavior (prompts, warnings, error messages)
- Security assessment: plaintext credentials? downgrade? user interaction required?
