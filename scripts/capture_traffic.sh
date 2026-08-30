#!/bin/bash
#
# capture_traffic.sh
#
# Captures a diverse tcpdump session by deliberately triggering
# different TCP flag behaviors (SYN, FIN, RST, sustained ACK/PSH),
# instead of just recording passive background traffic.
#
# IMPORTANT: Only run this on a machine/network you own or are
# authorized to monitor. Do not point the RST-generation step at
# any host you don't control or have permission to probe.
#
# Usage:
#   chmod +x capture_traffic.sh
#   sudo ./capture_traffic.sh [duration_seconds] [interface] [output_file]
#
# Example:
#   sudo ./capture_traffic.sh 300 eth0 tcpdump_session1.txt
#

set -e

DURATION=${1:-300}          # default 5 minutes
INTERFACE=${2:-eth0}        # default interface, change to en0 on Mac, etc.
OUTFILE=${3:-tcpdump_capture_$(date +%Y%m%d_%H%M%S).txt}

echo "=== Traffic capture starting ==="
echo "Duration:  ${DURATION}s"
echo "Interface: ${INTERFACE}"
echo "Output:    ${OUTFILE}"
echo "================================"

if [ "$EUID" -ne 0 ]; then
    echo "This script needs root/sudo to capture packets. Re-run with sudo."
    exit 1
fi

# Start tcpdump in the background, writing tshark-style summary lines
# (same format your parser.py already expects: time, IPs, ports, flags, Len=)
tcpdump -i "$INTERFACE" -tt -n tcp or udp -l 2>/dev/null > "$OUTFILE" &
TCPDUMP_PID=$!

echo "tcpdump running (PID $TCPDUMP_PID). Generating varied traffic..."
sleep 2

# --- 1. SYN-heavy: open many new connections in quick succession ---
echo "[1/5] Generating SYN traffic (new connections)..."
SITES=("google.com" "github.com" "wikipedia.org" "cloudflare.com" "amazon.com"
       "microsoft.com" "apple.com" "netflix.com" "reddit.com" "stackoverflow.com")
for site in "${SITES[@]}"; do
    curl -s -o /dev/null --max-time 1 "https://$site" &
done
wait
sleep 2

# --- 2. FIN-heavy: open-then-quickly-close connections ---
echo "[2/5] Generating FIN traffic (quick connection close)..."
for site in "${SITES[@]}"; do
    timeout 1 curl -s -o /dev/null "https://$site" &
done
wait
sleep 2

# --- 3. RST traffic: connect to a closed/filtered port on purpose ---
#     Only probes localhost - safe, doesn't touch external hosts.
echo "[3/5] Generating RST traffic (closed local port)..."
for port in 9991 9992 9993 9994 9995; do
    timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null || true
done
sleep 2

# --- 4. Sustained ACK/PSH-ACK: larger data transfer ---
echo "[4/5] Generating sustained ACK/PSH-ACK traffic (larger download)..."
curl -s -o /dev/null --max-time 15 "https://speed.hetzner.de/100MB.bin" || true
sleep 2

# --- 5. Idle period: natural background traffic ---
echo "[5/5] Idle period for natural background traffic..."
REMAINING=$((DURATION - 30))
if [ "$REMAINING" -gt 0 ]; then
    sleep "$REMAINING"
fi

echo "Stopping capture..."
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

LINE_COUNT=$(wc -l < "$OUTFILE")
echo "================================"
echo "Capture complete: $OUTFILE"
echo "Lines captured: $LINE_COUNT"
echo "================================"
echo "Run this multiple times across different sessions/days for more"
echo "variety, then concatenate the files before running parser.py."
