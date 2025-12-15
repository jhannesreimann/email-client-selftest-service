
### Mail Server Port Configuration (mail.nsipmail.de)

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              MAIL SERVER: mail.nsipmail.de (13.62.95.49)                        │
│                                        AWS EC2 · Ubuntu 22.04                                   │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                 │
│   IMAP (Dovecot)                    SMTP (Postfix)                   POP3 (Dovecot)             │
│   ══════════════                    ═══════════════                  ═════════════              │
│                                                                                                 │
│   ┌─────────────┐ ┌─────────────┐   ┌─────────────┐ ┌─────────────┐  ┌─────────────┐ ┌────────┐ │
│   │  Port 993   │ │  Port 143   │   │  Port 465   │ │  Port 587   │  │  Port 995   │ │Port 110│ │
│   │   IMAPS     │ │    IMAP     │   │   SMTPS     │ │ Submission  │  │   POP3S     │ │  POP3  │ │
│   │             │ │             │   │             │ │             │  │             │ │        │ │
│   │ Implicit TLS│ │  STARTTLS   │   │ Implicit TLS│ │  STARTTLS   │  │ Implicit TLS│ │STARTTLS│ │
│   │  (secure)   │ │ (vulnerable)│   │  (secure)   │ │ (vulnerable)│  │  (secure)   │ │(vulner)│ │
│   └──────┬──────┘ └──────┬──────┘   └──────┬──────┘ └──────┬──────┘  └──────┬──────┘ └───┬────┘ │
│          │               │                 │               │                │            │      │
│          ▼               ▼                 ▼               ▼                ▼            ▼      │
│   ┌─────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                  VULNERABILITY SETTINGS                                 │   │
│   ├─────────────────────────────────────────────────────────────────────────────────────────┤   │
│   │                                                                                         │   │
│   │   Dovecot (IMAP/POP3):                    Postfix (SMTP):                               │   │
│   │   ────────────────────                    ───────────────                               │   │
│   │   disable_plaintext_auth = no             smtpd_tls_auth_only = no                      │   │
│   │   ssl = yes (not required)                smtpd_tls_security_level = may                │   │
│   │                                                                                         │   │
│   │   → Server accepts LOGIN/AUTH commands even WITHOUT active TLS encryption!              │   │
│   │   → This allows credentials to be sent in plaintext if STARTTLS is stripped.            │   │
│   │                                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                 │
│   DNS Configuration:                                                                            │
│   ──────────────────                                                                            │
│   A     mail.nsipmail.de  →  13.62.95.49                                                        │
│   MX    nsipmail.de       →  mail.nsipmail.de                                                   │
│   TXT   nsipmail.de       →  v=spf1 mx ~all                                                     │
│                                                                                                 │
│   Note: Autodiscover DISABLED to force clients into "Heuristic Guessing" mode                   │
│                                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```
