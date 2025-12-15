# Client Self-Test Idea (Draft)

## Goal
Provide a simple way for a user to test whether their **email client** could be coerced into **downgrade-to-plaintext** behavior on mail protocols (SMTP/IMAP/POP3), i.e., whether the client might send credentials without encryption after STARTTLS is removed/broken.

The long-term vision could be a UI / webapp, but initially this is intended as a **script-driven workflow** with clear instructions.

## Intended User Experience (UX)
- The user should not need to install complex tooling.
- Ideally it should also work for users on **mobile (e.g., Android)**.
- The workflow can be **guided** (step-by-step instructions), because automatically configuring every client is unrealistic.

The self-test should output one of:
- **Vulnerable/Unsafe:** the client attempted or completed authentication in plaintext under the tested scenario.
- **Secure:** the client refuses to authenticate or refuses to proceed without TLS.
- **User-dependent / Unclear:** the client does not leak credentials automatically, but presents unsafe guidance (e.g., suggests disabling STARTTLS), or the outcome cannot be measured reliably without user input.

## How this relates to our current setup
### Current (local) reproduction setup
Right now, we run **mitmproxy in transparent mode** locally and load the paper’s attack scripts (T1–T4) from:
- `50-implementation/mitm-scripts/email-security/`

This works because we control the network path using iptables/netns and can modify traffic between client and server.

### Why that is hard for a user-facing self-test
If the proxy does **not** run on the user’s device or inside the user’s network path:
- We cannot transparently intercept/modify traffic.
- Many email clients do not support generic explicit TCP proxies for IMAP/SMTP.
- TLS interception (to read encrypted credentials) typically requires installing a custom CA certificate, which is explicitly something we want to avoid.

Therefore, we cannot simply “reuse the existing mitmproxy addons” in a user-facing test without requiring significant installation and setup.

## Key challenge: How to cover T1–T4 without a MITM proxy
The existing T1–T4 scripts are **MITM manipulations**. Without a proxy, the practical alternative is to simulate the same conditions via a **test server**.

### Core observation
In a STARTTLS stripping attack, the client ultimately experiences something like:
- STARTTLS is not available (capability missing), or
- STARTTLS fails / is rejected, or
- TLS breaks mid-handshake / after handshake.

A server can simulate those conditions directly.

## Proposed direction: Server-side test service (no proxy on client)
Run a dedicated “self-test” mail service (separate from the existing `mail.nsipmail.de` honeypot), which provides deterministic behaviors that approximate T1–T4.

### Mapping idea: MITM testcases -> server behaviors
- **T1 (capability stripping):** server simply does not advertise STARTTLS.
- **T3 (STARTTLS rejection):** server advertises STARTTLS but rejects the STARTTLS command.
- **T2 (ServerHello replacement / handshake tampering):** server accepts STARTTLS but intentionally breaks TLS handshake (approximation).
- **T4 (post-handshake disruption):** server completes TLS then intentionally disrupts protocol session.

### Measurement signal (important)
Instead of reading client credentials via MITM, the test service observes server-side whether the client sends:
- SMTP: `AUTH ...` before TLS
- IMAP: `LOGIN user pass` before TLS
- POP3: `USER` / `PASS` before TLS

For privacy/safety, the service should ideally log only:
- whether plaintext auth was attempted (yes/no)
- protocol + testcase + timestamp (and maybe a short pseudonymous session id)

## Auto-config / standard ports problem
### Issue
If we instruct a user to use “Auto-Config / Automatic setup”, many clients will probe **standard ports**:
- IMAP: 143/993
- SMTP: 587/465
- POP3: 110/995

If we put each testcase on a custom port, auto-config may not reach it.

### Options
1) **Per-testcase subdomain / host**, using standard ports
   - Example: `t1.selftest.example`, `t2.selftest.example`, ...
   - User selects auto-config but with a test email address tied to that subdomain.
   - Challenge: on STARTTLS ports there is no SNI; hosting multiple behaviors on the same IP/port is tricky.

2) **Per-testcase custom ports** (simpler technically)
   - Works well for manual configuration.
   - Less compatible with auto-config.

3) **Single host + standard ports + “server-side switching”**
   - A web UI/script sets “next testcase for this user/session”.
   - Risk: NAT/shared IPs, retries, parallel connections.

4) Provide explicit auto-config metadata (later)
   - SRV records / Thunderbird autoconfig XML to guide ports.
   - More implementation effort.

## Domain / infrastructure separation
We want this self-test environment to not break our existing local reproduction setup.

Proposed separation:
- Keep current honeypot: `mail.nsipmail.de` (Postfix/Dovecot; used for our local MITM tests)
- Add a separate self-test environment:
  - separate subdomain (e.g., `selftest.nsipmail.de`)
  - preferably separate VM/IP and/or separate ports
  - dedicated test services for SMTP/IMAP/POP3 behaviors

## What this enables (value)
- A repeatable, guided workflow to classify client behavior without requiring the user to run a transparent proxy.
- Can be used internally first; potentially opened publicly later.
- Provides a clear extension beyond paper replication: turning the research setup into a practical diagnostic.

## Open questions
- Which clients do we target first (Thunderbird vs mobile)?
- How much can we rely on user-provided observations (warnings, error messages)?
- How to handle privacy and abuse prevention if the service is public?
- How closely do we need to match the original paper’s T2/T4 semantics vs a behavior-equivalent approximation?

## Next steps (if we pursue this)
- Decide the infrastructure option (subdomains/IPs vs ports vs server-side switching)
- Prototype a minimal SMTP/IMAP test service for T1/T3 first (most directly linked to plaintext fallback)
- Define exact success criteria and what we log
- Write a short user guide / script output instructions
