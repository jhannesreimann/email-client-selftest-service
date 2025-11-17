# Server Infrastructure & Vulnerable Configuration Setup

**Project:** Replication of "A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems" (NDSS 2025)  
**Component:** Victim Mail Server (Target)

This document details the setup of the mail server used as the target for our client downgrade attacks. The server is deliberately configured to allow insecure authentication methods to test client "Auto-Detect" behaviors.

---

## TLDR
This document describes the deployment of a **vulnerable "Honey Pot" Mail Server** on AWS EC2 (Ubuntu 22.04) to replicate the NDSS 2025 paper findings.

* **Infrastructure:** Public AWS VM with Elastic IP (`13.62.95.49`) and valid domain (`mail.nsipmail.de`).
* **Software:** Postfix (SMTP) & Dovecot (IMAP/POP3) with valid Let's Encrypt certificates.
* **The Vulnerability:** The server is deliberately misconfigured to **allow plaintext authentication** (`AUTH PLAIN`) on STARTTLS ports (587, 143), while simultaneously offering secure Implicit TLS ports (465, 993).
* **Goal:** This setup allows us to test if email clients' "Auto-Detect" algorithms fall for a security downgrade attack (stripping STARTTLS) and send credentials in cleartext.

## 1. Infrastructure (AWS EC2)

We hosted the mail server on a public cloud instance to ensure accessibility for global DNS propagation and SSL certificate validation.

* **Provider:** AWS EC2
* **OS:** Ubuntu Server 22.04 LTS (Chosen for compatibility with the paper's methodology regarding certificate bundles).
* **Instance Type:** `t2.micro`
* **Network:** Static Public IP (Elastic IP): `13.62.95.49`

### Firewall Rules (Security Group)
The following inbound ports were opened to the public (`0.0.0.0/0`) to simulate a real-world mail server and allow Let's Encrypt validation:

| Protocol | Port | Service | Purpose |
| :--- | :--- | :--- | :--- |
| TCP | **22** | SSH | Remote Administration (Restricted source IP recommended) |
| TCP | **80** | HTTP | Certbot / Let's Encrypt Validation |
| TCP | **443** | HTTPS | Certbot / Let's Encrypt Validation |
| TCP | **25** | SMTP | Standard SMTP (MTA to MTA) |
| TCP | **465** | SMTPS | **Implicit TLS** (Secure) |
| TCP | **587** | Submission | **STARTTLS** (Vulnerable Target) |
| TCP | **143** | IMAP | **STARTTLS** (Vulnerable Target) |
| TCP | **993** | IMAPS | **Implicit TLS** (Secure) |
| TCP | **110** | POP3 | **STARTTLS** (Vulnerable Target) |
| TCP | **995** | POP3S | **Implicit TLS** (Secure) |

---

## 2. Domain & DNS Configuration

* **Domain:** `nsipmail.de` (Registered via Strato)
* **Strategy:** "Autodiscover" features were explicitly **disabled** to force email clients into "Heuristic Guessing" mode, which is the specific mechanism we are attacking.

### DNS Records

| Type | Host | Value | Purpose |
| :--- | :--- | :--- | :--- |
| **A** | `mail` | `13.62.95.49` | Points `mail.nsipmail.de` to our AWS VM. |
| **MX** | `@` | `mail.nsipmail.de` | Designates our VM as the mail handler for the domain. |
| **TXT**| `@` | `v=spf1 mx ~all` | SPF Record to legitimize the server (Softfail). |

---

## 3. Software Installation & Base Setup

The software stack mirrors the setup described in the NDSS paper:

```bash
# System Update
sudo apt update && sudo apt upgrade -y

# Install Mail Stack
sudo apt install postfix dovecot-core dovecot-imapd dovecot-pop3d -y
# (Selected "Internet Site" during Postfix setup)

# Install TLS Tooling
sudo apt install certbot -y
```

### SSL Certificates

We generated a valid, trusted certificate to test the "Happy Path" (secure connection) alongside the vulnerable path.
Bash

```bash
sudo certbot certonly --standalone -d mail.nsipmail.de
```

    Cert Path: /etc/letsencrypt/live/mail.nsipmail.de/fullchain.pem

    Key Path: /etc/letsencrypt/live/mail.nsipmail.de/privkey.pem

## 4. Vulnerable Configuration ( The "Honey Pot")

To replicate the findings, the server must support both high-security methods (Implicit TLS) and insecure methods (Plaintext Auth via STARTTLS) simultaneously.

### A. Postfix Configuration (SMTP)

File: ```/etc/postfix/main.cf``` We enabled SASL authentication and explicitly allowed plaintext auth over unencrypted connections.

```TOML
# Identity
myhostname = mail.nsipmail.de

# TLS Parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/mail.nsipmail.de/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mail.nsipmail.de/privkey.pem
smtpd_use_tls=yes
smtpd_tls_security_level=may

# SASL Auth (Connecting to Dovecot)
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# *** VULNERABILITY SETTING ***
# Allows AUTH PLAIN command even if TLS is not active yet.
# This allows the client to send the password in cleartext if STARTTLS is stripped.
smtpd_tls_auth_only = no
```

File: ```/etc/postfix/master.cf``` We enabled the submission ports and ensured the vulnerability applies to Port 587.

```TOML
# Port 587 (Submission / STARTTLS)
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=may
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=no  # Explicit weakness for this port

# Port 465 (SMTPS / Implicit TLS) -> The Secure Alternative
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
```

### B. Dovecot Configuration (IMAP/POP3)

File: ```/etc/dovecot/conf.d/10-auth.conf```

```TOML
# *** VULNERABILITY SETTING ***
# Allows login without encryption
disable_plaintext_auth = no
auth_mechanisms = plain login
```

File: ```/etc/dovecot/conf.d/10-ssl.conf```

```TOML
# "yes" means: SSL is supported/offered, but NOT required.
# (Default is often "required", which would block our attack)
ssl = yes

ssl_cert = </etc/letsencrypt/live/mail.nsipmail.de/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.nsipmail.de/privkey.pem
```

File: ```/etc/dovecot/conf.d/10-master.conf``` We created the socket for Postfix to communicate with Dovecot.

```TOML
service auth {
  # ...
  # Socket for Postfix
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
```

### C. Permission Fix

To prevent the ```Connection closed``` error (where Postfix cannot access the Dovecot auth socket), we added the ```dovecot``` user to the ```postfix``` group:

```bash
sudo adduser dovecot postfix
sudo systemctl restart dovecot
sudo systemctl restart postfix
```

## 5. Verification

We verified the vulnerability using ```telnet```. The server successfully accepts plaintext authentication on STARTTLS ports without enforcing encryption.

Test User: ```testuser``` / ```password123```

### Proof of SMTP Vulnerability (Port 587):

```bash
telnet mail.nsipmail.de 587
EHLO test.com
# Server announces: 250-AUTH PLAIN LOGIN (despite not being encrypted)
AUTH PLAIN AHRlc3R1c2VyAHBhc3N3b3JkMTIz  # (Base64 encoded credentials)
# Server responds: 235 2.7.0 Authentication successful
```

### Proof of IMAP Vulnerability (Port 143):

```bash
telnet mail.nsipmail.de 143
a1 LOGIN testuser password123
# Server responds: a1 OK [...] Logged in
```