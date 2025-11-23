# 60-findings – Client Findings

This directory contains structured findings for tested email clients, based on the NDSS 2025 reproduction.

Current clients:
- Thunderbird 140.4.0esr on Kali GNU/Linux Rolling (x86_64)

See individual markdown files in this folder for detailed results per client and test case.

## 📊 Client Vulnerability Matrix

Legend:
- ✅ **Secure:** Client detects attack and aborts connection (no plaintext credentials sent).
- ❌ **Vulnerable:** Client falls back to plaintext authentication (credentials exposed).
- ⚠️ **User-Dependent:** Client shows error/warning, but suggests insecure action (e.g. "Disable STARTTLS").
- ⚪ **Untested:** Not yet tested.

### STARTTLS Stripping (T1), ServerHello Replacement (T2), Command Rejection (T3), Session Disruption (T4)

| Client | OS / Platform | Protocol | T1 | T2 | T3 | T4 | Certificate (C1-C4) | Findings File |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Thunderbird 140.4.0esr** | Kali Linux | **IMAP** | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | [Details](./Thunderbird_Kali_T1.md) |
| | | **SMTP** | ⚠️ | ⚪ | ⚪ | ⚪ | ⚪ | [Details](./Thunderbird_Kali_T1.md) |
| | | **POP3** | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | |
| | | | | | | | | |

---

## 📝 Notes

- **Thunderbird (SMTP T1):** Client fails securely (no plaintext auth) but explicitly suggests disabling STARTTLS in the error message. This is marked as ⚠️ **User-Dependent** risk.
