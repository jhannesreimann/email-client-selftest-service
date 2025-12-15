# automated test setup

example for thunderbird client

# 1. configure network 

```
cd 50-implementation/test-setup
export NS=ns-tb
```

clean up if necessary
```
sudo ./teardown_ns.sh $NS
```

create network namespace, veth pair, configure NAT, redirect all IMAP/POP3/SMTP ports to mitmproxy
```
sudo ./setup-ns.sh $NS
```

to see created namespace: 
```
ip netns list
```

# 2. start mitmproxy

**make sure you use customized mitmproxy with addons**
see  https://github.com/tls-downgrade/email-security

Example (run mitmproxy inside the namespace and load a test-case script from this repository):

```
sudo ip netns exec $NS mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost \
  -s ../mitm-scripts/email-security/imap/t1.py
```

```
ps aux | grep mitm
```
stop with
```
sudo pkill mitmdump
```

## example:
```
sudo ip netns exec ns-tb mitmproxy --set spoof-source-address --ssl-insecure \
  --mode transparent --showhost \
  -s ../mitm-scripts/email-security/imap/t1.py
```

# 3. run client in ns

1) recommended - with account setup in thunderbird UI
```
sudo ./run-client-in-ns.sh ns-tb thunderbird

[+] Launching Thunderbird in namespace ns-tb as user sagen
[+] Launching with default profile
[+] Done.

```
proceed in UI



2) or use static configs

```
sudo ./run-client-in-ns.sh ns-tb thunderbird testprofile

[+] Launching Thunderbird in namespace ns-tb as user sagen
[+] Launching with profile: testprofile
[+] Done.
```
