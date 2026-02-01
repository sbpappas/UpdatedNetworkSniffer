#!/bin/bash

IFACE=${1:-en0}

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)" # finds the base directory 
OUT="$BASE_DIR/data/traffic.pcap"

echo "[*] Capturing on interface: $IFACE" #what is iface
sudo tshark -i "$IFACE" -w "$OUT"
