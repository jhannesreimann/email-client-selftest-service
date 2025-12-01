#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Usage: sudo ./client-setup.sh <namespace> <client> [test-profile-name]"
    exit 1
fi

NS="$1"
CLIENT="$2"
PROFILE_NAME="$3"

if [ -z "$NS" ] || [ -z "$CLIENT" ]; then
    echo "Usage: sudo ./client-setup.sh <namespace> <client> [test-profile-name]"
    exit 1
fi

REALUSER="${SUDO_USER:-$USER}"
REALHOME=$(eval echo "~$REALUSER")

echo "[+] Using real user: $REALUSER"
echo "[+] Real user home: $REALHOME"

# if no profile name provided finish
if [ -z "$PROFILE_NAME" ]; then
    echo "[+] Done. No client test profile provided."
    exit 0
fi

# Determine setup script based on client
if [ "$CLIENT" = "thunderbird" ]; then
    echo "[+] Creating Thunderbird profile: $PROFILE_NAME"
    # Create Thunderbird profile
    ip netns exec "$NS" runuser -u "$REALUSER" -- \
        thunderbird -CreateProfile $PROFILE_NAME
    # Run user-specific setup script inside namespace
    ip netns exec "$NS" runuser -u "$REALUSER" -- \
        env REALUSER="$REALUSER" REALHOME="$REALHOME" \
        bash setup-thunderbird.sh
    echo "[+] Thunderbird profile configured."
else
    echo "[-] Client '$CLIENT' not supported."
    exit 1
fi
