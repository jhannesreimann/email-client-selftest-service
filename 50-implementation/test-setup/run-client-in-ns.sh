#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run using: sudo ./run-client-in-ns.sh <namespace> <client> [test-profile-name]"
    exit 1
fi

NS="$1"
CLIENT="$2"
PROFILE_NAME="$3"

if [ -z "$NS" ] || [ -z "$CLIENT" ]; then
    echo "Usage: sudo ./run-client-in-ns.sh <namespace> <client> [test-profile-name]"
    exit 1
fi

REALUSER="${SUDO_USER:-$USER}"

# Determine setup script based on client
if [ "$CLIENT" = "thunderbird" ]; then
    echo "[+] Launching Thunderbird in namespace $NS as user $REALUSER"

    if [ -n "$PROFILE_NAME" ]; then
        echo "[+] Launching with profile: $PROFILE_NAME"
        ip netns exec "$NS" runuser -u "$REALUSER" -- \
            thunderbird -P "$PROFILE_NAME" &
    else
        echo "[+] Launching with default profile"
        ip netns exec "$NS" runuser -u "$REALUSER" -- \
            thunderbird &
    fi

    echo "[+] Done."
else
    echo "[-] Client '$CLIENT' not supported."
    exit 1
fi
