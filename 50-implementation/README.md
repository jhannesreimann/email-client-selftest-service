# Implementation & Setup

This directory contains all practical implementation work for the project. 

Our main deliverables are packaged as easy-to-run tools. For high-level instructions on how to run these as demos, please see the [Main README](../README.md#🚀-how-to-setup-configure-and-run-the-demos).

## 🚀 Main Deliverables (Demos)

1. **[Selftest Service (`selftest-service/`)](./selftest-service/)**
   * A client-facing web service to test email clients against STARTTLS downgrade attacks without requiring a local proxy.
   * **Setup/Config:** See [`selftest-service/README.md`](./selftest-service/README.md) for AWS deployment instructions.
   * **Run:** Available publicly at https://selftest.nsipmail.de.

2. **[Server Configuration Scanner (`server-checker/`)](./server-checker/)**
   * A bash script for mail server administrators to audit Postfix/Dovecot configurations for downgrade vulnerabilities.
   * **Setup/Config:** No installation required, just download and run as root on the mail server.
   * **Run:** `./server-checker/server-checker-for-admin.sh`

---

## 🛠️ Infrastructure & Manual Testing

The following directories contain the underlying infrastructure and manual testing scripts used during our research phase:

* **`server-setup/`**: Documentation on how we configured our vulnerable target mail server (`mail.nsipmail.de`). See [`server-setup/README.md`](./server-setup/README.md).
* **`mitm-scripts/`**: The original attack scripts from the NDSS 2025 paper.
* **`test-setup/`**: Various test configurations.

### Target Server Access
- **SSH:** `ssh ubuntu@13.62.95.49` (key-based auth)
- **Test Account:** `testuser@nsipmail.de` / `password123`
- **Logs:** `/var/log/mail.log` (Postfix/Dovecot)

### Manual Server Verification
You can manually verify the server vulnerability (plaintext auth allowed on port 587) using telnet:
```bash
telnet mail.nsipmail.de 587
EHLO test.com
# Should show: 250-AUTH PLAIN LOGIN (without TLS!)
AUTH PLAIN AHRlc3R1c2VyAHBhc3N3b3JkMTIz
# Should respond: 235 2.7.0 Authentication successful
```

### Manual MITM Testing Methodology (Legacy)
Before developing the Selftest Service, we used the following manual process with mitmproxy:
1. Configure client network to route through mitmproxy
2. Use "Auto-Detect" or "Manual" feature to configure account
3. Run test cases T1-T4
4. Capture traffic logs and authentication attempts
5. Document: Does client send credentials in plaintext?
