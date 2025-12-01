#!/usr/bin/env bash
set -e

# Must be run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

# Namespace provided as argument
NS="${1}"

echo "[+] Cleaning namespace '$NS', veth, and NAT MASQUERADE rule"

# Delete namespace (safe)
ip netns delete "$NS" 2>/dev/null || true

# Delete host-side veth (safe)
ip link delete veth0 2>/dev/null || true

# Remove MASQUERADE rule for this namespace subnet (safe)
iptables -t nat -D POSTROUTING -s 10.200.1.0/24 -j MASQUERADE 2>/dev/null || true

echo "[+] Done"

