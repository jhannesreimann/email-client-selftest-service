# Mail Server STARTTLS Audit Script

A lightweight Bash audit script that checks **Postfix** and **Dovecot** configurations for common security misconfigurations related to **STARTTLS downgrade attacks**.

The script inspects active configuration files and reports insecure settings along with fixes recommendations.


## Usage

### console output mode
```bash
./server-checker-for-admin.sh
```

example output:
```
=== Mail Server Vulnerability Audit ===
This script checks Postfix/Dovecot configs for vulnerability to STARTTLS downgrade.

[Postfix] smtpd_tls_security_level=may
  Reason: TLS is optional; STARTTLS stripping is possible
  Recommendation: smtpd_tls_security_level = encrypt
  File: /etc/postfix/main.cf

[Postfix] smtpd_tls_auth_only=no
  Reason: AUTH allowed before TLS negotiation
  Recommendation: smtpd_tls_auth_only = yes
  File: /etc/postfix/main.cf

[Postfix]   -o smtpd_tls_security_level=may
  Reason: submission service allows STARTTLS downgrade
  Recommendation: smtpd_tls_security_level = encrypt
  File: /etc/postfix/master.cf

[Postfix]   -o smtpd_tls_auth_only=no
  Reason: submission service allows AUTH before TLS
  Recommendation: smtpd_tls_auth_only = yes
  File: /etc/postfix/master.cf

Postfix config documentation:
  main.cf -> man 5 postconf, https://www.postfix.org/postconf.5.html
  master.cf -> man 5 master, http://www.postfix.org/master.5.html

[Dovecot] disable_plaintext_auth=no
  Reason: Allows cleartext authentication
  Recommendation: disable_plaintext_auth = yes
  File: /etc/dovecot/conf.d/10-auth.conf

[Dovecot] ssl=yes
  Reason: TLS is optional; downgrade possible
  Recommendation: ssl = required
  File: /etc/dovecot/conf.d/10-ssl.conf

[Dovecot] auth_mechanisms = plain login
  Reason: Plain or LOGIN auth enabled — safe only with mandatory TLS
  Recommendation: Use mandatory TLS with PLAIN/LOGIN or disable them
  File: /etc/dovecot/conf.d/10-auth.conf

Dovecot config documentation:
  https://doc.dovecot.org/latest/
```

### output to JSON
```bash
./server-checker-for-admin.sh -o result.json
```


## Features

- Detects whether Postfix and/or Dovecot are installed
- Identifies cases where TLS is optional instead of mandatory
- Detects insecure authentication options (plain, login)
- Multiple config file support:
  - Dovecot: Handles split(`conf.d/`) and monolithic(`dovecot.conf`) configurations
  - Postfix: Supports `main.cf` and `master.cf`
- Two output modes:
  - Human-readable console output (default)
  - Machine-readable JSON report via specifying output file `-o result.json`
- Configurable paths: override default config file locations via CLI options
- Provides references to configuration documentation

## What It Checks

### Postfix
if the following insecure options are in `main.cf`:
- `smtpd_tls_security_level = may`
- `smtpd_tls_auth_only = no`

in `master.cf`:
- submission service overrides of values from `main.cf`

### Dovecot
- `disable_plaintext_auth = no`
- `ssl = yes` (TLS optional instead of required)
- `auth_mechanisms` enabling `PLAIN` or `LOGIN`
