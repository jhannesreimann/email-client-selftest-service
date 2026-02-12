#!/bin/bash

# Fix for "missing or unsuitable terminal" when connecting from kitty/alacritty
export TERM=xterm-256color

# Configuration paths (adjust if you use custom paths)
MODE_FILE="/var/lib/nsip-selftest/mode.json"
EVENTS_FILE="/var/log/nsip-selftest/events.jsonl"

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed. Please install it: sudo apt-get install jq"
    exit 1
fi

if ! command -v tmux &> /dev/null; then
    echo "Error: 'tmux' is not installed. Please install it: sudo apt-get install tmux"
    exit 1
fi

if [ ! -f "$MODE_FILE" ]; then
    echo "Warning: $MODE_FILE does not exist yet (service not started?). Creating empty dummy."
    sudo mkdir -p "$(dirname "$MODE_FILE")"
    echo "{}" | sudo tee "$MODE_FILE" > /dev/null
fi

if [ ! -f "$EVENTS_FILE" ]; then
    echo "Warning: $EVENTS_FILE does not exist yet. Creating empty dummy."
    sudo mkdir -p "$(dirname "$EVENTS_FILE")"
    sudo touch "$EVENTS_FILE"
    sudo chmod 666 "$EVENTS_FILE"
fi

SESSION="nsip-demo"

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null

# Start new session
tmux new-session -d -s "$SESSION"

# --- Pane 1 (Top): Watch Mode Store ---
# Shows active overrides (IPs in test modes) and guided runs
tmux send-keys -t "$SESSION" "watch -n 0.5 --color 'echo \"=== SERVER STATE (mode.json) ===\"; jq -C . \"$MODE_FILE\"'" C-m

# Split window vertically
tmux split-window -v -t "$SESSION"

# --- Pane 2 (Bottom): Live Events Log ---
# Tails events and formats them with jq. filtering for readability.
# We show timestamp, event type, IP, proto, mode, and tls status.
FILTER='{ts: .ts, event: .event, ip: .client_ip, proto: .proto, mode: .mode, tls: .tls, res: .result}'
tmux send-keys -t "$SESSION" "echo '=== LIVE EVENTS (events.jsonl) ==='; tail -f -n 20 \"$EVENTS_FILE\" | jq --unbuffered -C '$FILTER'" C-m

# Resize: Give the log a bit more space usually, or 50/50. Let's do 50/50.
tmux select-layout -t "$SESSION" tiled

# Attach to session
tmux attach-session -t "$SESSION"
