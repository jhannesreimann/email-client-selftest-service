# PQC Fingerprinting (arXiv:2503.17830v1) - Project Summary

This document summarizes the findings of the paper "Fingerprinting Implementations of Cryptographic Primitives and Protocols that Use Post-Quantum Algorithms" and outlines a potential recreation plan for our project.

---

## 1. Key Findings

The paper's core thesis is that Post-Quantum Cryptography (PQC) algorithms have unique and measurable resource "fingerprints" that make them distinguishable from classical algorithms and even from each other.

This fingerprinting was proven in three distinct areas:

1.  **Library Fingerprinting (Section 3):**
    * By measuring **local resource usage** (CPU cycles and memory), an ML model can be trained to distinguish different cryptographic operations.
    * **Classical vs. PQ:** Achieved 98-100% accuracy (e.g., ECDH vs. Kyber).
    * **PQ vs. PQ:** Achieved 86-97% accuracy (e.g., Kyber vs. SIKE).
    * **Library vs. Library:** Achieved 96-100% accuracy (e.g., `liboqs`'s Kyber vs. `CIRCL`'s Kyber).
    * **Key Insight:** The ML model learned that **memory usage** (like `VmSize`, `VmRSS`) is a far more robust and reliable feature than CPU cycles, especially on "noisy" systems with background processes (Dataset2).

2.  **Protocol Fingerprinting (Section 4):**
    * This method *does not use ML*. It relies on passively observing network traffic (`.pcap` files).
    * For protocols like TLS 1.3 and SSH, the key exchange materials are sent in plaintext during the handshake.
    * The public keys/ciphertexts for PQ algorithms are **"exponentially larger"** than classical ones (e.g., 1000+ bytes for Kyber vs. 32 bytes for ECDH).
    * This massive size difference makes them **"easily distinguishable"** just by parsing the key share field in the handshake packets.

3.  **Real-World Application (Section 6):**
    * The authors integrated their methods into Cisco's `QUARTZ` risk analysis tool.
    * They scanned the **Tranco 1M list** and found **4,988 unique IPs** (mostly belonging to Cloudflare and Google) that appeared to support PQC key exchange in their TLS handshakes.

---

## 2. Methodology & Recreation Plan

The paper offers two distinct and achievable paths for recreation.

### Path A: Library Fingerprinting (Recreating Sec. 3)
This is the **Machine Learning** approach. We would be recreating the ML model that fingerprints local crypto operations.

1.  **Setup:** On a Linux VM, install the crypto libraries used in the paper: `liboqs` (C), `CIRCL` (Go), and `libtomcrypt` (C for classical).
2.  **Data Collection:**
    * Write scripts (using the paper's provided code) to loop through the key exchange and signature algorithms thousands of times.
    * While the scripts run, use Linux tools to capture resource usage:
        * `perf`: To get per-core CPU cycle counts.
        * `/proc/[pid]/status`: To get memory metrics (`VmSize`, `VmRSS`, `VMData`, etc.).
3.  **Analysis:**
    * Recreate the "noisy" **Dataset2** by running CPU-intensive background tasks (like `stress-ng` or the paper's own scripts).
    * Feed the resulting CSV data into a Python ML model (e.g., `scikit-learn` with XGBoost/Random Forest).
    * **Goal:** Replicate the high accuracy scores from the paper (e.g., 98% for Classical vs. PQ).

### Path B: Protocol Fingerprinting (Recreating Sec. 4)
This is the **Network Analysis** approach. This is simpler and requires no ML.

1.  **Setup:**
    * Install a PQ-enabled TLS server (e.g., `OQS-OpenSSL`) on one VM.
    * Install a standard TLS server (e.g., standard `OpenSSL`) on another VM.
2.  **Data Collection:**
    * Use `tcpdump` or `Wireshark` to capture the traffic while connecting to both servers using a standard client (like `curl` or `openssl s_client`).
3.  **Analysis:**
    * Load the `.pcap` files into Wireshark (or parse with `scapy`).
    * Filter for `tls.handshake` and inspect the `ClientHello` and `ServerHello` messages.
    * **Goal:** Find the "Key Share" extension, extract its byte length, and show the massive difference between the classical and PQ connections.




---

## 3. Potential for New Findings (Our Contribution)

A simple recreation of Path B (Sec. 4) is "trivial" (as we discussed). To make it a strong project, we could add one of these new contributions:

1.  **ML on Network Traffic:** The paper *doesn't* use ML for protocol analysis. We could try! Instead of just looking at key size, we could train an ML model on *other* network features (packet size, inter-arrival time, handshake latency) to see if we can fingerprint the protocol *without* deep packet inspection.
2.  **Test Defenses (ECH):** The paper mentions Encrypted Client Hello (ECH) as a potential defense. We could set up an ECH-enabled server and *test this hypothesis*. Can our fingerprinting (Path B) defeat ECH? Does ECH successfully hide the PQ key share size?
3.  **Re-run Tranco Scan:** The paper's scan is from early 2025. We could re-run their Tranco 1M scan methodology and compare our results from [aktuelles Datum einfügen] to theirs. This would show the *growth* of PQC adoption, which is a new finding.
4.  **Analyze Signature Fragmentation:** The paper notes that PQ *signatures* (not key exchange) are so large they will *cause packet fragmentation*. This is just a hypothesis in the paper. We could be the first to actually implement a PQ signature in a TLS handshake (e.g., Dilithium) and practically measure/analyze this fragmentation pattern.

---

## 4. Advantages and Disadvantages

### ✅ Advantages
* **Source Code is Available:** This is the biggest advantage. The authors provide all their data collection scripts, analysis code, and ML models in an anonymous repository. This saves us weeks of work.
* **Two Clear Paths:** The project is flexible. We can choose the more complex ML-focused project (Sec. 3) or the more straightforward networking project (Sec. 4).
* **High Feasibility:** Both paths are highly achievable within a semester. The tools (`liboqs`, `Wireshark`, `perf`) are all open-source and well-documented.
* **Highly Relevant:** PQC migration is one of the most important topics in network security *right now*.
* **Clear Success Metrics:** Our goal is clear: either replicate the ML model's accuracy or replicate the network observation of key sizes.

### ❌ Disadvantages
* **Trivial Finding (Sec. 4):** As noted, the core finding of the network analysis (that big keys are big) is obvious. We **must** extend this with one of the "New Findings" ideas to make it a valuable project.
* **Niche Setup (Sec. 3):** The ML path is less of a "network security" project and more of a "systems/ML" project. It requires compiling specific C (`liboqs`) and Go (`CIRCL`) libraries and using Linux-specific performance tools (`perf`, `/proc/`), which might be tedious.