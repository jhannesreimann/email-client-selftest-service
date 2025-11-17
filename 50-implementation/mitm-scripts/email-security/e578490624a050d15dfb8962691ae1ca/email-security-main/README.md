#### Overview
This is the test cases used in [A Multifaceted Study on the Use of TLS and
Auto-detect in Email Ecosystems](https://dx.doi.org/10.14722/ndss.2025.240532). Read the paper for more details.

#### Explanation on files
To accommodate different syntax, you will see there are three folders with the respective protocols.
- T1: STARTTLS stripping
- T2: Replace incoming ServerHello in TLS negotiation
- T3: Reject STARTTLS command
- T4: Disrupt a complete TLS handshake

##### Setup

1. Setup the mitmproxy according to their official website.

2. Modify the mitmproxy with the below command

```
git clone https://github.com/tls-downgrade/email-security.git
cp -r  imap/ pop3/ smtp/ ./mitmproxy
cp next_layer.py ./mitmproxy/addons/
```

3. Run the mitmproxy with the following command:
```
mitmproxy --set spoof-source-address --ssl-insecure --mode transparent --showhost -s <folder/file.py>
```
