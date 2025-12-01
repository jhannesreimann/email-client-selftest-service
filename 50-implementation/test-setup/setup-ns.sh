#!/usr/bin/env bash
set -e

MITM_PORT=8080

# Must be run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root: sudo ./setup-ns.sh <ns-name>"
  exit 1
fi

# Specify namespace name
NS="${1}"
if [ -z "$NS" ]; then
  echo "No netns name specified. Usage: sudo ./setup-ns.sh <ns-name>"
  exit 1
fi

echo "[+] Enable IPv4 forwarding..."
bash "./ipv4forward.sh"

echo "[+] Create network namespace..."
ip netns add $NS

echo "[+] Setup veth pair..."
ip link add veth0 type veth peer name veth-ns

ip link set veth-ns netns $NS
## veth-ns is connected to NS while veth0 is connected to default namespace already

# put veth0 and veth2 on the same subnet(private IP subnet) so they can communicate
# in default NS
ip addr add 10.200.1.1/24 dev veth0
ip link set veth0 up
# in custom NS
ip netns exec $NS ip addr add 10.200.1.2/24 dev veth-ns
ip netns exec $NS ip link set lo up
ip netns exec $NS ip link set veth-ns up
ip netns exec $NS ip route add default via 10.200.1.1

echo "[+] Configure NAT..."
# to be able to get responses from internet
iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -j MASQUERADE

echo "[+] Redirect all IMAP/POP3/SMTP ports to mitmproxy..."
for port in 143 993 110 995 587 465 25; do
    ip netns exec $NS iptables -t nat -A OUTPUT -p tcp --dport $port \
        -j REDIRECT --to-port $MITM_PORT
done
