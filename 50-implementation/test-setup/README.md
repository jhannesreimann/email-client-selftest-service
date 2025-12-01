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

```
sudo ./run-mitm.sh <network_namespace> <script.py>
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
sudo ./run-mitm.sh ns-tb imap/t1.py 
[INFO] Assumes mitmdump at ./.venv/bin/mitmdump customize if necessary
[INFO] This script creates a 'logs' directory in the current folder
[+] Logs (stdout&stderr) → /home/sagen/Desktop/nsproj/mitmproxy/logs/imap_t1_20251201_110450.log
[+] Mitmproxy flow → /home/sagen/Desktop/nsproj/mitmproxy/logs/imap_t1_20251201_110450.mitm (read with: mitmdump -nr /home/sagen/Desktop/nsproj/mitmproxy/logs/imap_t1_20251201_110450.mitm)
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
