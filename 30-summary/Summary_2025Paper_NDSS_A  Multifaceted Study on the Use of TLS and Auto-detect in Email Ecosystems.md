# Email Auto-Detect Vulnerabilities (NDSS 2025) - Project Summary

This document summarizes the findings of the paper "A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems" and outlines a potential recreation plan for our project.

---

## 1. Key Findings

The paper's core thesis is that the **"auto-detect"** feature in modern email clients (IMAP, POP3, SMTP) is often poorly implemented and creates severe security vulnerabilities, including **plaintext credential theft**, even when the server is securely configured.

The attack exploits the difference between two TLS modes:
1.  **Implicit TLS (I-TLS):** The secure method. The client connects directly to a dedicated secure port (e.g., 993 for IMAPS) and starts a TLS handshake immediately.
2.  **Opportunistic TLS (O-TLS / STARTTLS):** The vulnerable method. The client connects to a plaintext port (e.g., 143 for IMAP), communicates in plaintext, and then attempts to "upgrade" the connection to TLS by sending a `STARTTLS` command.

This `STARTTLS` process can be manipulated by a Man-in-the-Middle (MITM) attacker.

**Key Findings from the Paper:**
* **Clients are Vulnerable:** The authors tested 49 email clients. Of the 30 that support auto-detect, **14 were found to have noticeable security downgrade** vulnerabilities.
* **Credential Theft:** These vulnerabilities allowed an active MITM attacker to **downgrade the connection to plaintext (no-TLS)**. 8 of these clients were so flawed they leaked credentials to a *passive* attacker.
* **Flawed Auto-Detect Logic:** The vulnerability is not just a simple bug. Some clients (e.g., Edison Mail, TypeApp) implement auto-detect by **concurrently probing multiple ports at once** (e.g., port 993 for I-TLS, port 143 for STARTTLS, and port 143 for *no-TLS*). They then use whichever connection "wins the race" and responds fastest. An attacker can easily win this race by immediately blocking the secure ports and offering an insecure plaintext connection, which the client then automatically selects.
* **Certificate Validation is Broken:** 19 of the 49 clients (nearly 40%) improperly validated TLS certificates, for example by accepting expired or self-signed certificates without user warning, or with a "User Insecure" prompt.
* **Setup Guides are Misleading:** The authors analyzed 1102 setup guides from universities and found that many admins **explicitly instruct users to use the "auto-detect" feature** or "blindly accept" certificate warnings, directly leading users into these traps.
* **Servers are Mostly Secure:** The paper concludes that the servers themselves are generally well-configured and support secure I-TLS. The weakest links are the **clients and the user-facing setup guides**.

---

## 2. Methodology & Recreation Plan

This project is **highly reproducible**. The paper's methodology in **Section III-A (Email Client Testing)** provides a clear, step-by-step blueprint for us to follow.

### Path: Recreating the Client-Side Downgrade Attack (Sec. III-A)
This is a practical, software-based attack.

1.  **Setup the Testbed (Server):**
    * We need a Linux VM (the paper used AWS EC2).
    * Install and configure a full email server stack. The paper explicitly names the open-source tools:
        * **Postfix** (for SMTP)
        * **Dovecot** (for IMAP and POP3)
    * This server must be configured to offer *all* connection methods: I-TLS (on ports 993/995/465), O-TLS (STARTTLS on ports 143/110/587), and plaintext authentication on the O-TLS ports.

2.  **Implement the MITM Attack:**
    * Use the *exact* tool from the paper: **`mitmproxy`**.
    * We will write a `mitmproxy` script (in Python) to act as the attacker, intercepting traffic between the client and our server.
    * The script will implement the paper's key **Test Cases (T1-T4)**.

3.  **Security Downgrade Test Cases (Detailed):**
    * **T1:** The classic STARTTLS stripping attack where an active MITM removes the STARTTLS capability offered by the server, as shown in Fig. 2. This tests whether the client will fallback to no-TLS when opportunistic TLS is not advertised by the server.
    * **T2:** The active MITM replaces ServerHello with a cleartext message indicating TLS is not available after the client sent a ClientHello for TLS negotiation, as shown in Fig. 3. This tests how a client would respond to an unexpected message at the TLS level.
    * **T3:** Keep the STARTTLS capability offered by the server, but when the client agrees to start TLS negotiation in cleartext stage (after client’s STARTTLS but before its ClientHello), we send a cleartext message indicating TLS is not available, as shown in Fig. 4. Following RFC3207, a client needs to decide whether to proceed with the SMTP session when TLS upgrade is not possible, and this test determines the client’s decision on that. Although the idea of this test originates from the SMTP RFC, it can be adopted to test IMAP and POP3 as well, by sending the appropriate error response to STARTTLS (i.e., 454 TLS not available for SMTP, BAD for IMAP, and -ERR for POP3).
    * **T4:** When the client and server agree to use STARTTLS to opportunistically upgrade to TLS, disrupt the TLS session by sending arbitrary messages (e.g., NOOP) to see how the client responds, as shown in Fig. 5. This tests whether the client can handle disruption after a successful handshake.

    **Context on Auto-Detect:** For auto-detect, our tests focus on the case where the client heuristically guesses the connection parameters, without relying on Autoconfig, Exchange AutoDiscover and DNS SRV. This is because those 3 mechanisms are not always available, and an active attacker can force the client to use heuristic guessing by blocking the corresponding DNS queries (type SRV for DNS SRV, and type A/AAAA for Autoconfig/AutoDiscover subdomains).

4.  **Test Clients & Analyze:**
    * Install a selection of email clients (e.g., Thunderbird, Apple Mail, K-9 Mail, Outlook) on test devices (VMs, test-phones).
    * Configure the clients' network settings to route all traffic through our `mitmproxy` instance.
    * Run the **"auto-detect"** setup process for each client.
    * **Goal:** Observe the `mitmproxy` traffic log. We succeed if we see the client attempt a plaintext `AUTH PLAIN` (or similar) command, sending the username and password unencrypted after our downgrade attack.

5.  **(Optional) Certificate Validation:**
    * Recreate the paper's certificate test cases (**C1-C4**) by generating a **self-signed certificate (C1)**, an **expired certificate (C2)**, or a **mismatched domain certificate (C4)**.
    * Configure our Dovecot/Postfix server to use these bad certificates.
    * **Goal:** Test which clients silently accept these certificates, which present a "User Insecure" prompt, and which correctly reject them.

---

## 3. Potential for New Findings (Our Contribution)

A simple recreation is a great baseline. We can easily add new findings by:

1.  **Testing Current Versions:** The paper used client versions from late 2023/early 2024. We can test the **latest 2025/2026 versions** of the *same clients* they found vulnerable (like Apple Mail, Edison Mail) to see if the vendors have patched these specific downgrade flaws. (Apple was planning a fix for late 2024).
2.  **Testing New Clients:** We can test popular clients that were *not* included in their list of 49.
3.  **Analyzing HPI Setup Guides:** We can replicate **Section V (Findings on Real-World Deployments)** in a "micro-study." We'll analyze the official HPI IT support documentation for email setup. Do they recommend "auto-detect"? Do they warn users about certificate errors?
4.  **Investigating Concurrent Auto-Detect:** We can specifically try to replicate the "race condition" attack on clients like Edison Mail by implementing a `mitmproxy` script that adds a *slight delay* to secure ports while *instantly* responding to the plaintext port.

---

## 4. Advantages and Disadvantages

### ✅ Advantages
* **Excellent Feasibility:** This project is highly achievable. It's 100% software-based. It does not require rare hardware (like Rowhammer) or massive datasets (like the PQC or Fault papers).
* **Clear Roadmap:** The paper's methodology (Section III-A) is a literal step-by-step instruction manual for our project.
* **Open Source Tools:** The entire toolchain (`Postfix`, `Dovecot`, `mitmproxy`) is free, open-source, and well-documented.
* **High-Impact Result:** Successfully capturing a plaintext password via a downgrade attack is a classic, impressive, and easy-to-demonstrate "Network Security in Practice" outcome.
* **Code Available:** The paper notes their test cases are publicly available on GitHub, which is a massive head start. (https://github.com/tls-downgrade?tab=repositories)

### ❌ Disadvantages
* **Server Setup Complexity:** Setting up a full email server stack (Postfix + Dovecot) with multiple ports and security protocols correctly configured is non-trivial and can be time-consuming.
* **Client Sourcing & Setup:** Acquiring and testing a *range* of clients across different operating systems (Android, iOS, Windows, macOS) requires setting up multiple test VMs and/E-Mail-Clients.
* **MITM Configuration:** Configuring client devices (especially mobile phones like iOS and Android) to trust and route all their traffic through our `mitmproxy` instance (including installing a custom CA certificate) can be tricky.