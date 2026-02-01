#!/bin/bash

IFACE=${1:-en0}
OUT=../data/traffic.pcap

echo "[*] Capturing on interface: $IFACE"
sudo tshark -i "$IFACE" -w "$OUT"
