#!/usr/bin/env bash

CURRENT_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)

if [ "$CURRENT_FORWARD" -eq 1 ];  then
    echo "[+] IPv4 forwarding is already enabled"
else
    echo "[+] Enabling IPv4 forwarding"
    sudo sysctl -w net.ipv4.ip_forward=1
fi
