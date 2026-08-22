# Implementation

The practical part of the project, as opposed to the paperwork in the numbered folders around it. The [root README](../README.md) has the big picture.

## Tools

- [`selftest-service/`](./selftest-service/): the client-facing self-test service. A Python SMTP/IMAP server that misbehaves on purpose (baseline plus the paper's T1-T4 disruption patterns) and a FastAPI WebUI that runs test sessions and computes verdicts. Run instructions and a full self-hosting walkthrough are in [its README](./selftest-service/README.md).
- [`server-checker/`](./server-checker/): a Bash script for mail server admins. It audits active Postfix/Dovecot configurations for settings that allow plaintext auth or make STARTTLS stripping possible. No install needed: download, `chmod +x`, run with sudo. Details in [its README](./server-checker/README.md).

## Lab infrastructure (historical)

Everything below was live during the course (October 2025 to March 2026). The AWS instances behind it are gone, so these directories document what we did rather than anything still running.

- [`server-setup/`](./server-setup/): how we built the deliberately vulnerable Postfix/Dovecot target (`mail.nsipmail.de`) used for manual client testing.
- [`mitm-scripts/`](./mitm-scripts/): the original T1-T4 attack scripts from the NDSS 2025 paper authors, plus their TLS version downgrade PoC. Used with mitmproxy for the tests recorded in [`60-findings/client/`](../60-findings/client/).
- [`test-setup/`](./test-setup/): network namespaces and iptables rules that routed a local Thunderbird through mitmproxy transparently.

For context on how we got from the proxy-based setup to the public self-test service, see the idea sketch in [`10-planning/client-self-test-idea.md`](../10-planning/client-self-test-idea.md) and the design notes in [`selftest-service/PAPER_PARITY_AND_NEXT_STEPS.md`](./selftest-service/PAPER_PARITY_AND_NEXT_STEPS.md). The short version: asking users to install mitmproxy and redirect their traffic was a non-starter for a public tool, so we simulated the misbehaving server instead.
