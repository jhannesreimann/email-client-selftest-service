# Implementation & Setup

This directory contains all practical implementation work:
Manual setup-related:
* server configuration in `server-setup/` - See [`server-setup/README.md`](./server-setup/README.md)
* attack scripts `mitm-scripts/`
* test configurations `test-setup/`
* Selftest service - `selftest-service/`
* Server config scanner - `server-checker/`

---

### Server Access
- **SSH:** `ssh ubuntu@13.62.95.49` (key-based auth)
- **Test Account:** `testuser@nsipmail.de` / `password123`
- **Logs:** `/var/log/mail.log` (Postfix/Dovecot)

### Quick Verification
```bash
# Test server vulnerability (plaintext auth on port 587)
telnet mail.nsipmail.de 587
EHLO test.com
# Should show: 250-AUTH PLAIN LOGIN (without TLS!)
AUTH PLAIN AHRlc3R1c2VyAHBhc3N3b3JkMTIz
# Should respond: 235 2.7.0 Authentication successful
```

### Testing Methodology:
1. Configure client network to route through mitmproxy
2. Use "Auto-Detect" or "Manual" feature to configure account
3. Run test cases T1-T4
4. Capture traffic logs and authentication attempts
5. Document: Does client send credentials in plaintext?
