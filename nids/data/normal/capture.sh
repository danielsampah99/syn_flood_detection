#!/bin/bash

set -e  # Exit on error

# Set variables

OUTPUT_DIR="/tmp"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILE_OUTPUT="$OUTPUT_DIR/normal_${TIMESTAMP}.pcap"

# Ensure output dir is accessible to root
sudo chown -R "$USER:$USER" "$OUTPUT_DIR"

echo "Starting normal packet capture on loopback interface for 10 minutes..."
echo "Capturing traffic on port 2121 (FTP)..."

# Let tshark create the file itself
sudo tshark -i lo -w "$FILE_OUTPUT" -f "tcp port 2121" -a duration:6000

# Fix file ownership after capture
sudo chown "$USER:$USER" "$FILE_OUTPUT"

# Post-capture check
if [ -f "$FILE_OUTPUT" ]; then
    FILE_SIZE=$(du -h "$FILE_OUTPUT" | cut -f1)
    echo "Normal Capture succeeded"
    echo "File location: $FILE_OUTPUT"
    echo "File size: $FILE_SIZE"
else
    echo "Capture failed"
    exit 1
fi
