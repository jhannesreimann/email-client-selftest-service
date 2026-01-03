# Paper parity & next steps for the Selftest Service

This document explains how to evolve the current **selftest-service** (server simulation + WebUI) so that its client-testing methodology becomes closer to the paper’s T1–T4 testcases.

It also documents two key design decisions:

- Why we currently **simulate the server behavior** instead of deploying a real **MITM proxy**.
- Why we currently **deprioritize POP3**, even though T1–T4 can be applied to POP3 in principle.

---

## 1) Baseline: what the current selftest-service does

The current implementation is a **public, client-facing self-test**:

- The user starts a session in the WebUI.
- The WebUI sets a temporary mode override (TTL-based) for the user’s public IP.
- The user configures a mail client to connect to the selftest host and performs actions (IMAP refresh / SMTP send).
- The mail server logs privacy-safe events (no passwords) and includes a session code derived from the username (`test-SESSION`).

The WebUI supports two workflows:

- **Guided mode (recommended)**: a fixed 9-step sequence (Baseline, Immediate T1–T4, Two-phase T1–T4) with per-step credentials and a final result table.
- **Advanced mode**: manually pick a scenario and testcase.

Implementation details that matter for interpretation:

- The mode override is stored per public IP and appears in logs as `override_session` (when present).
- The authoritative session grouping is derived from the username and appears as `session`.
- Pre-auth events (connect/capability/ehlo/starttls) intentionally use `session=null` to avoid attributing old traffic to a new session.

This setup is designed to answer:

- “Does this client ever attempt **authentication without TLS** when STARTTLS is disrupted or unavailable?”

Outcome computation (current behavior):

- `FAIL` if an auth/login attempt was observed with `tls=false` (plaintext credentials exposure).
- `PASS` if a TLS-protected auth/login attempt was observed and no plaintext auth was seen.
- `INCONCLUSIVE` if no auth/login attempt was observed (client aborted early, got stuck retrying, or never reached auth).
- `SKIPPED` for guided steps that were explicitly skipped in the UI.

---

## 2) Paper testcases (T1–T4) and how they map to our approach

The paper defines:

- **T1**: MITM removes STARTTLS capability (client sees no STARTTLS advertised).
- **T2**: MITM replaces `ServerHello` with cleartext after client sends `ClientHello`.
- **T3**: STARTTLS is advertised, but when client requests STARTTLS, attacker responds with a cleartext “TLS not available” message.
- **T4**: After successful TLS handshake, attacker disrupts the TLS session by sending arbitrary messages (e.g., NOOP) and observes client response.

### How server-simulation maps to T1–T4

Even though the paper describes an **active MITM**, the *client-observed behavior* can often be approximated by a **test server** that behaves as-if an attacker were present.

- **T1 (capability stripping)**
  - Simulation: do not advertise STARTTLS in `EHLO` (SMTP) / `CAPABILITY` (IMAP).
  - Paper parity: high for the *client decision point* “STARTTLS not offered”.

  Additional behavior for public self-tests:

  - Many clients prefer implicit TLS ports (`IMAPS 993`, `SMTPS 465`) and would never reach the STARTTLS decision point.
  - To keep the test focused on STARTTLS downgrade behavior, the current implementation intentionally **disconnects immediately** on implicit TLS ports in modes `t1`–`t4`. This forces clients to retry on STARTTLS ports (`143`, `587`, optionally `25`).

- **T3 (reject STARTTLS with explicit error)**
  - Simulation: advertise STARTTLS, but return an error when the client issues STARTTLS.
    - SMTP: `454 TLS not available`
    - IMAP: `BAD`
    - POP3: `-ERR`
  - Paper parity: high for the *client decision point* “upgrade refused”.

- **T2 (unexpected cleartext at TLS level)**
  - Simulation: after accepting STARTTLS (or for implicit TLS ports, after the client starts TLS), force the TLS negotiation to fail in a way that resembles “cleartext instead of TLS”.
  - Paper parity: medium. This is harder to reproduce faithfully without a MITM because “replace ServerHello” is very specific to being on-path.

- **T4 (post-handshake disruption)**
  - Simulation: complete TLS handshake, then inject protocol-invalid/unexpected data (e.g., `NOOP`) and close the connection.
  - Paper parity: medium/high depending on exact client behavior being measured.

---

## 3) Why we currently simulate instead of using a real MITM proxy

### 3.1 Practical reason: public, client-facing self-test constraints

A real MITM testbed (like in a lab) typically requires one of:

- installing a custom CA certificate,
- using a local proxy with OS-level trust,
- or controlling network routing (Wi-Fi AP / VPN / captive portal).

For a **public self-test** (especially for non-technical users and mobile clients), these requirements are a major barrier.

Server simulation has the advantage that:

- it works with “just configure the account”,
- it does not require additional software,
- it is deployable on a public host with standard ports.

In addition, the guided workflow improves reproducibility:

- per-step credentials reduce cross-contamination between modes,
- the user is prompted when to trigger actions (IMAP refresh / SMTP send),
- the service can compute comparable outcomes across clients.

### 3.2 Scientific reason: isolate the client decision point

Many important client decisions are made based on **what the client sees**:

- STARTTLS advertised or not,
- STARTTLS accepted or rejected,
- TLS negotiation succeeded or failed,
- connection disrupted at a specific stage.

A simulated test server can create these conditions deterministically, which helps reproducibility.

### 3.3 Security/legal reason: MITM can look like active interception

A MITM that modifies traffic “in the wild” can be risky from a legal/ethical standpoint unless done purely on a lab network under explicit control. A public service should avoid anything that resembles third-party interception.

---

## 4) Could we do it with a proxy/MITM anyway? Yes — and how.

If you want **maximum paper parity**, you can add a proxy-based testing mode. There are two main architectures:

### Option A: Transparent “Relay MITM” between client and a real upstream provider

- Client connects to `selftest.nsipmail.de` (the MITM endpoint).
- The proxy connects to a real upstream server (e.g., a controlled mail server instance).
- The proxy modifies the connection at specific phases to implement T1–T4.

Implementation idea:

- Build a TCP proxy that understands SMTP/IMAP enough to:
  - parse server capability lines,
  - remove STARTTLS tokens (T1),
  - respond with protocol-correct “TLS not available” (T3),
  - after client sends TLS ClientHello, inject cleartext instead of continuing TLS (T2),
  - after TLS handshake, inject unexpected messages / disrupt stream (T4).

Challenges:

- For TLS, after STARTTLS the proxy must either:
  - become a TLS MITM (requires client trust), or
  - terminate the connection / inject cleartext failure without full MITM.

### Option B: Controlled lab MITM (closest to the paper)

This is the “academic” setup:

- You control a local network (Wi-Fi AP or VPN).
- You run a true MITM that modifies client↔server traffic.
- You can deploy trusted certificates or route traffic such that TLS can be intercepted.

This yields the closest reproduction of “active MITM replaces ServerHello (T2)”, but is not suitable for a public self-test.

### Recommended hybrid approach

- Keep **simulation** as the public self-test default.
- Add an optional **lab-only MITM tool** (separate component) for experiments requiring maximum fidelity.

---

## 5) Why POP3 is deprioritized (for now)

Even though T1–T4 can be adapted to POP3 (as the paper notes), there are good reasons to de-scope it initially.

### 5.1 Client-side effort and user friction

To run the self-test, the user must configure a mail account and trigger traffic.

- Many modern clients default to IMAP.
- POP3 configuration is often hidden behind “manual setup” or legacy options.
- On mobile, POP3 support is frequently missing or non-standard.

So POP3 adds significant user friction and reduces test completion rate.

### 5.2 Engineering effort vs incremental value

Adding POP3 properly means:

- Implement POP3 protocol parsing and state machine (CAPA, STLS, USER/PASS, STAT/LIST/RETR, etc.).
- Support ports `110` (STARTTLS) and `995` (implicit TLS).
- Add POP3-specific logging and WebUI guidance.

In practice, the most widely used and security-relevant client configurations today are typically **IMAP + SMTP submission**, so POP3 has lower marginal impact for the initial public service.

### 5.3 Measurement focus

The main research question is about **plaintext authentication behavior under TLS disruption**.

IMAP + SMTP already covers:

- incoming authentication (IMAP LOGIN), and
- outgoing authentication (SMTP AUTH).

If POP3 coverage is needed later, it can be added as an extension once the SMTP/IMAP methodology is stable.

---

## 6) What is still missing to get closer to paper parity (practical roadmap)

Below is a concrete roadmap grouped by impact.

### 6.1 Multi-client testing and comparison to the paper (high impact)

The most important next step is to run the guided workflow across multiple clients/platforms and compare observed outcomes to the paper.

Suggested evaluation dimensions:

- Client UI prompts (downgrade suggestions) vs wire-observed behavior.
- Differences between IMAP vs SMTP behavior.
- Differences between `immediate` vs `two_phase` semantics.
- Frequency of “never reaches auth” cases and what protocol stage clients stop at.

### 6.2 Mode fidelity alignment to T1–T4 (high impact)

Ensure the simulated modes match the paper’s decision points precisely.

- **T1**
  - SMTP: remove STARTTLS from `EHLO` capabilities.
  - IMAP: remove STARTTLS from `CAPABILITY`.

- **T3**
  - Advertise STARTTLS but on STARTTLS command return:
    - SMTP: `454 TLS not available`
    - IMAP: tagged `BAD` response

- **T2**
  - Paper-specific: “replace ServerHello with cleartext after ClientHello”.
  - In simulation, approximate by:
    - letting the client enter TLS negotiation and then providing an unexpected cleartext payload / closing.
  - Also log it as “T2-like” and clearly document the approximation.

- **T4**
  - After successful TLS handshake, disrupt the TLS session.
  - In the current implementation, “disrupt” means: after the STARTTLS handshake succeeds, inject unexpected data (e.g., `NOOP`) on the TLS channel and then close.

Two-phase semantics (current behavior):

- For `two_phase`, the service treats the testcase as “activated” only after a TLS-protected authentication attempt was observed.
- The guided workflow then instructs the user to retry to observe post-activation behavior.

### 6.3 Protocol realism to trigger client behavior (medium/high)

### 6.3.1 Autodetect / heuristic-guessing limitation for public self-tests

The paper explicitly studies the case where the client is forced into **heuristic guessing** by blocking discovery mechanisms (Autoconfig/AutoDiscover/DNS SRV).

In a public self-test, this is hard to reproduce for some clients because there is an additional discovery path that is **outside of our domain control**:

- Some clients (notably Thunderbird) can query the Mozilla/Thunderbird **ISPDB** (a central provider database) and obtain server settings for the email domain.

This has an important consequence:

- Even if we disable DNS-based discovery (no SRV, and **NXDOMAIN** for `autoconfig.*` / `autodiscover.*` subdomains), the client may still not enter heuristic guessing, because it can directly use ISPDB-provided endpoints (e.g., a hosted-provider default like `imap.<provider>.de`, `smtp.<provider>.de`).

In the current public deployment, we rely on simple A records (e.g., `imap.selftest...`, `smtp.selftest...`, `mail.selftest...`) and do not expose SRV records.

Why this cannot be fixed purely server-side:

- The ISPDB request is an outbound request made by the client to a third-party host.
- Our self-test service only observes connections that actually reach our SMTP/IMAP listeners. If the client never attempts to connect to our hostnames/ports, we cannot influence the discovery decision.
- Under the project goal "the client should not need any special setup", we cannot require users to change Thunderbird settings or install custom DNS/firewall rules.

Practical workarounds (not aligned with the strict "no client changes" goal):

- **Network-side blocking** of the ISPDB host (lab/controlled network), which matches the paper's attacker assumption (blocking discovery queries).
- Use an email domain under a different organizational domain that is not mapped in ISPDB/provider heuristics, so that the client has no ISPDB configuration to fall back to.

Practical workaround implemented in the WebUI:

- Use a nip.io-derived autodetect domain based on the server IP (e.g., `test-SESSION@<public-ip>.nip.io`) so the email domain is unlikely to match an ISPDB entry.

Resulting scope decision for the public service:

- For some clients/providers, the public self-test cannot reliably force heuristic guessing without either a controlled network environment or a different email domain. Therefore, heuristic-guessing experiments may need to be documented as "lab-only" or "best-effort" rather than guaranteed for all users.

Some clients only reach certain decision points if the server appears realistic.

- IMAP:
  - Expand support for typical commands (LIST/SELECT/STATUS/UID FETCH/IDLE).
  - Ensure the state machine is consistent enough that clients keep trying.

- SMTP:
  - Ensure the post-AUTH flow resembles a real submission service enough that “Send” attempts complete.

This improves reproducibility of client behavior.

### 6.4 Session and isolation model (medium)

Paper experiments are controlled; public selftests face NAT/shared IP issues.

To reduce cross-user interference:

- Move from “mode per IP” to “mode per session token” (or IP+session).
- Or pin the mode to a session code extracted from the username.

In the current guided workflow, this risk is reduced by using fresh credentials per step, but public NAT/shared-IP environments can still cause interference.

### 6.5 Add a lab-only MITM tool (optional, for maximum parity)

If you need strict T2 parity and true MITM semantics:

- Build a separate “lab harness” component.
- Keep public self-test server-simulation as the default.

### 6.6 POP3 (optional, later)

If required for completeness:

- Add POP3 server with ports `110`/`995`.
- Implement T1–T4 equivalents (CAPA/STLS/cleartext errors).
- Update WebUI and docs.

---

## 7) Recommended next concrete steps (minimal set)

If the goal is “as close as practical to the paper, for a public self-test”:

1) Run guided tests across **multiple clients** and compare results to the paper; document discrepancies.
2) Tighten **T1–T4 semantics** where needed (especially T2/T4 approximation boundaries).
3) Consider extending scope to **POP3** if the client matrix suggests it adds meaningful coverage.
4) Consider adding **certificate-related experiments** as a separate track (lab-friendly), if needed for Phase II.

This yields a robust public service that approximates the paper’s threat model at the decision points most relevant to plaintext auth fallback.
