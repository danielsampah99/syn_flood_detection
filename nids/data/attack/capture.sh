#!/bin/bash
# capture_attack.sh - Capture attack traffic (SYN flood) for 2 minutes

set -e

OUTPUT_DIR="/tmp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILE_OUTPUT="$OUTPUT_DIR/attack_${TIMESTAMP}.pcap"

echo "Starting attack packet capture on loopback interface for 2 minutes..."
echo "Capturing traffic on port 2121 (FTP) during SYN flood attack..."

sudo tshark -i lo -w "$FILE_OUTPUT" -f "tcp port 2121" -a duration:120

sudo chown "$USER:$USER" "$FILE_OUTPUT"

if [ -f "$FILE_OUTPUT" ]; then
    FILE_SIZE=$(du -h "$FILE_OUTPUT" | cut -f1)
    echo "Attack capture succeeded"
    echo "File location: $FILE_OUTPUT"
    echo "File size: $FILE_SIZE"
else
    echo "Capture failed"
    exit 1
fi
