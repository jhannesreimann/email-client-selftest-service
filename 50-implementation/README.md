# Implementation & Setup

This directory contains all practical implementation work, including server setup, attack scripts, and test configurations for the TLS/Email security project.

## 🎯 Quick Status Overview

| Component | Status | Details |
|-----------|--------|---------|
| **Email Server** | ✅ Operational | AWS EC2 @ `mail.nsipmail.de` (13.62.95.49) |
| **Vulnerable Config** | ✅ Verified | Postfix + Dovecot allow plaintext auth |
| **MITM Scripts** | ✅ Ready | T1-T4 test cases + TLS downgrade PoC |
| **Client Testing** | 🔄 In Progress | Setting up test environment |
| **Certificate Tests** | 📋 Planned | Phase II: C1-C4 test certificates |

**Next Milestone:** Complete mitmproxy setup and run first client test (T1 - STARTTLS stripping)

---

## 📁 Current Directory Structure

```
50-implementation/
├── server-setup/           # ✅ Email server configuration (COMPLETED)
│   └── README.md          # Detailed AWS EC2 setup documentation
│                          # - Postfix + Dovecot configuration
│                          # - Domain: mail.nsipmail.de (13.62.95.49)
│                          # - Vulnerable "Honey Pot" setup
│                          # - Let's Encrypt certificates
│
├── mitm-scripts/          # ✅ MITM attack implementations (READY)
│   ├── email-security/    # Test Cases T1-T4 for email protocols
│   │   └── email-security-main/
│   │       ├── smtp/      # T1-T4 for SMTP (Port 587)
│   │       ├── imap/      # T1-T4 for IMAP (Port 143)
│   │       ├── pop3/      # T1-T4 for POP3 (Port 110)
│   │       └── next_layer.py  # mitmproxy layer modification
│   │
│   └── tls-downgrade/     # TLS version downgrade PoC
│       └── tls-downgrade-main/
│           ├── downgrade_poc.py   # Main downgrade attack script
│           ├── client_hello.py    # ClientHello parser
│           ├── proxy.py           # Proxy configuration
│           └── next_layer.py      # Layer handling
│
└── client-testing/        # 🔄 To be added: Client test results
    ├── test-results/      # Test logs per client
    └── client-configs/    # Client setup documentation
```

---

## 🎯 Project Context

This implementation recreates and extends the research from:

**"A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems" (NDSS 2025)**

### Core Components

#### 1. Email Server Stack (Testbed) ✅ OPERATIONAL

**Infrastructure:** AWS EC2 Ubuntu 22.04  
**Domain:** `mail.nsipmail.de` (13.62.95.49)  
**Status:** Fully configured and accessible

- **Postfix (SMTP):** 
  - Vulnerable Configuration: `smtpd_tls_auth_only = no` (allows plaintext AUTH)
  - Port 587: STARTTLS (vulnerable target)
  - Port 465: Implicit TLS/SMTPS (secure baseline)
  
- **Dovecot (IMAP/POP3):**
  - Vulnerable Configuration: `disable_plaintext_auth = no`
  - Port 143: IMAP with STARTTLS (vulnerable target)
  - Port 993: IMAPS with Implicit TLS (secure baseline)
  - Port 110: POP3 with STARTTLS (vulnerable target)
  - Port 995: POP3S with Implicit TLS (secure baseline)

- **TLS Certificates:** Valid Let's Encrypt certificates
- **Verification:** Plaintext authentication confirmed via telnet testing

**📖 Full Documentation:** See [`server-setup/README.md`](./server-setup/README.md)

---

#### 2. MITM Attack Framework ✅ READY FOR DEPLOYMENT

**Repository 1: `email-security/`** (Original Paper Test Cases)
- **Source:** https://github.com/tls-downgrade/email-security
- **Purpose:** Protocol-specific test cases T1-T4 for SMTP, IMAP, POP3

**Available Test Cases:**
- **T1 - STARTTLS Stripping:** Removes STARTTLS capability from server's response
  - Implementation: `smtp/t1.py`, `imap/t1.py`, `pop3/t1.py`
  - Attack: Strips `250-STARTTLS` from EHLO response (SMTP)
  - Result: Client falls back to plaintext authentication

- **T2 - ServerHello Replacement:** Replaces TLS ServerHello with error message
  - Implementation: `smtp/t2.py`, `imap/t2.py`, `pop3/t2.py`
  - Attack: Intercepts TLS negotiation, injects rejection message
  - Result: Client abandons TLS upgrade, uses plaintext

- **T3 - STARTTLS Command Rejection:** Rejects client's STARTTLS request
  - Implementation: `smtp/t3.py`, `imap/t3.py`, `pop3/t3.py`
  - Attack: Responds with error to STARTTLS command
  - Result: Tests client's fallback behavior per RFC

- **T4 - Post-Handshake Disruption:** Disrupts established TLS session
  - Implementation: `smtp/t4.py`, `imap/t4.py`, `pop3/t4.py`
  - Attack: Sends arbitrary messages (e.g., NOOP) after handshake
  - Result: Tests session resilience

**Repository 2: `tls-downgrade/`** (TLS Version Downgrade PoC)
- **Source:** https://github.com/tls-downgrade/tls-downgrade
- **Purpose:** Version downgrade attack (TLS 1.3 → TLS 1.2 → SSLv3)

**Core Scripts:**
- **`downgrade_poc.py`:** Main attack script
  - Parses ClientHello to detect supported TLS versions
  - Forces version downgrade by manipulating handshake
  - Logs downgrade attempts and success rates

- **`client_hello.py`:** TLS handshake parser
  - Extracts client TLS version from ClientHello
  - Parses extensions (SNI, supported versions)
  - Identifies cipher suites

- **`proxy.py`:** Transparent proxy configuration
- **`next_layer.py`:** mitmproxy layer modification (shared with email-security)

**Usage:**
```bash
# Email protocol test cases (T1-T4)
mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost -s smtp/t1.py

# TLS version downgrade
mitmproxy -s downgrade_poc.py
```

---

#### 3. Certificate Validation Tests 🔄 PLANNED

Test certificates to be generated:
- **C1:** Self-signed certificate
- **C2:** Expired certificate  
- **C3:** Wrong certificate chain
- **C4:** Domain mismatch certificate

**Status:** Server currently uses valid Let's Encrypt cert. Test certificates will be generated for Phase II.

---

#### 4. Client Testing 🔄 IN PROGRESS

**Target Clients:**
- TBD

**Testing Methodology:**
1. Configure client network to route through mitmproxy
2. Use "Auto-Detect" feature to configure account
3. Run test cases T1-T4
4. Capture traffic logs and authentication attempts
5. Document: Does client send credentials in plaintext?

**Status:** Awaiting client device setup and mitmproxy network configuration

---

## 🔗 External Resources

### Original Research
- **Paper GitHub:** https://github.com/tls-downgrade?tab=repositories
- **Email Security Tools:** https://github.com/tls-downgrade/email-security
- **TLS Downgrade Scripts:** https://github.com/tls-downgrade/tls-downgrade

### Project Documentation
- **Detailed Summary:** See [`30-summary/Summary_2025Paper_NDSS_A Multifaceted Study...`](../30-summary/)
- **Meeting Notes:** See [`20-protocol/`](../20-protocol/) for implementation decisions

---

## 🚀 Getting Started

### Current Status
✅ **Server:** Operational at `mail.nsipmail.de` (AWS EC2)  
✅ **MITM Scripts:** Ready in `mitm-scripts/` directories  
🔄 **Client Testing:** Setup in progress  

### Next Steps for Testing

#### 1. mitmproxy Setup (Local)
```bash
# Install mitmproxy
pip install mitmproxy

# Clone/Navigate to test case directory
cd 50-implementation/mitm-scripts/email-security/*/email-security-main/

# Modify mitmproxy installation (one-time setup)
# Copy protocol folders and next_layer.py to mitmproxy source
cp -r smtp/ imap/ pop3/ <mitmproxy-path>/
cp next_layer.py <mitmproxy-path>/addons/

# Run test case (example: SMTP T1)
mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost -s smtp/t1.py
```

#### 2. Network Configuration
- Configure test device to route traffic through mitmproxy
- Install mitmproxy CA certificate on client devices
- For transparent mode: Set up iptables rules for traffic redirection

#### 3. Client Testing Workflow
1. **Configure Client:** Use "Auto-Detect" feature
   - Server: `mail.nsipmail.de`
   - User: `testuser` / Password: `password123`
2. **Start mitmproxy** with desired test case (T1-T4)
3. **Observe Traffic:** Watch for plaintext AUTH commands
4. **Document Results:** Save logs to `client-testing/test-results/`

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

---

## 📊 Implementation Progress

### ✅ Completed (Phase I)

**1. Server Infrastructure**
- AWS EC2 instance deployed and configured
- Domain registration and DNS setup (`mail.nsipmail.de`)
- Postfix + Dovecot installation and vulnerable configuration
- Let's Encrypt SSL certificates obtained
- Firewall rules and port configuration
- Telnet verification of plaintext authentication

**2. Attack Scripts**
- GitHub repositories cloned and organized
- Test cases T1-T4 for SMTP, IMAP, POP3 available
- TLS downgrade PoC scripts ready
- mitmproxy integration scripts prepared

**3. Documentation**
- Server setup fully documented in `server-setup/README.md`
- Attack methodology understood and scripts analyzed
- Reference to original paper's GitHub repositories

### 🔄 In Progress (Phase I → Phase II)

**4. Client Testing Environment**
- [ ] mitmproxy installation and configuration on test machine
- [ ] Network routing setup (transparent proxy mode)
- [ ] Test client installation (Thunderbird, K-9 Mail, etc.)
- [ ] mitmproxy CA certificate distribution to clients
- [ ] First test run with T1 (STARTTLS stripping)

**5. Testing & Analysis**
- [ ] Run all test cases (T1-T4) against target clients
- [ ] Document which clients are vulnerable
- [ ] Compare results with original paper (2023/2024 versions)
- [ ] Analyze auto-detect implementation differences
- [ ] Create test result documentation

### 📋 Planned (Phase II)

**6. Certificate Validation Testing**
- [ ] Generate test certificates (C1-C4)
- [ ] Configure Dovecot/Postfix with test certificates
- [ ] Test client certificate validation behavior
- [ ] Document which clients accept invalid certificates

**7. Extended Analysis**
- [ ] Test additional clients not in original paper
- [ ] Analyze HPI email setup guides
- [ ] Investigate "race condition" attacks (Edison Mail, TypeApp)
- [ ] Performance measurements and statistics

**8. Deliverables**
- [ ] Demo video of successful credential capture
- [ ] Detailed test results spreadsheet
- [ ] Comparison table: Our findings vs. NDSS 2025 paper
- [ ] Recommendations for secure email client configuration

---

## 📈 Evaluation Tracking

This directory supports the **Practice (Implementation)** evaluation component:
- **Phase I (10%):** ✅ Server setup completed, MITM framework ready
- **Phase II (20%):** 🔄 Client testing in progress, analysis pending

**Documentation Standards:**
- ✅ Setup steps and configurations (server-setup/README.md)
- 🔄 Test results and observations (to be added in client-testing/)
- ✅ Original paper script analysis (documented in this README)
- 🔄 Challenges and solutions (to be documented during testing)