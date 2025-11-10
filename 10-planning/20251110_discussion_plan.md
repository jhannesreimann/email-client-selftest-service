# # paper to reproduce:

name: A Multifaceted Study on the Use of TLS and Auto-detect in Email Ecosystems
venue: Network and Distributed System Security (NDSS) Symposium 2025

[detailed summary by Jhness](https://gitlab.hpi.de/seceng/studentspace/nsip-2025/team-2/-/blob/main/30-summary/Summary_2025Paper_NDSS_A%20%20Multifaceted%20Study%20on%20the%20Use%20of%20TLS%20and%20Auto-detect%20in%20Email%20Ecosystems.md?ref_type=heads)

[pdf here](https://gitlab.hpi.de/seceng/studentspace/nsip-2025/team-2/-/blob/main/40-references/2025Paper_NDSS_A%20Multifaceted%20Study%20on%20the%20Use%20of%20TLS%20and%20Auto-detect%20in%20Email%20Ecosystems.pdf?ref_type=heads)

# Is it a good match for us?

Probably, yes

## advantages:
As Jhness writes in the summary:

1) the topic actually has enough "networking", downgrade attack with MiTM is a classic

2) the topic is relevant: email security impacts everyone

3) the paper is feasible to reproduce for us:
* it's software-based, no specific hardware required (like Rowhammer)
* no massive datasets analysis (like the PQC or Fault papers)
* clear methodology (in Section III-A)
* Open Source Tools: Postfix, Dovecot, mitmproxy

**BUT**: "we purchased a domain from GoDaddy" and set up mail servers on an AWS EC2 instance

* Code Available: https://github.com/tls-downgrade?tab=repositories

## disadvantages & discussion:

apart from the possible complications of the setup [listed by Jhness](https://gitlab.hpi.de/seceng/studentspace/nsip-2025/team-2/-/blob/main/30-summary/Summary_2025Paper_NDSS_A%20%20Multifaceted%20Study%20on%20the%20Use%20of%20TLS%20and%20Auto-detect%20in%20Email%20Ecosystems.md?ref_type=heads#-disadvantages), here are possible drawbacks and questions of this topic as a seminar project:

### setup

0) apparently we need a domain, how to get it for free?

### project scope

1) the paper evaluates 49 email clients,
uncovering previously unknown vulnerabilities re-
lated to auto-detect and certificate validation when
TLS is enabled

* Probably most of the clients are fixed since the paper release? if we find that everything is secure in the updated clients, what do we do?
* do we necessarily need 49 clients? We could start with evaluating just the clients recommended in the setup guide of our university, then add more if necessary

2) NO LINUX! - paper tests on 4 major operating systems: Android, IOS, MACOS, Windows
* Our contribution can be running tests on Linux:)

3)  evaluating 1102 setup guides
* we will just evaluate 2 - HPI and Uni Potsdam?

I checked the HPI tech introduction section on email setup - there's a room for client-dependent vulnerabilities since they recommend to allow automatic configuration by the mail client:
```
We have already suc-
cessfully tried the following email clients that you can use:
Windows Outlook, Thunderbird
Linux Thunderbird
MacOS Apple Mail, Outlook, Thunderbird
Android GMail, FairEmail, Outlook
iOS/iPadOS Apple Mail, Outlook
If possible, ask your mail client to automatically configure an Microsoft/Office 365 email account
```
