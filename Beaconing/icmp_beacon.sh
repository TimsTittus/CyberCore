#!/bin/bash

TARGET="0.0.0.0" # Replace with actual target IP
INTERVAL=5
LOG_FILE="/tmp/icmp_beacon.log"

echo "[*] ICMP Beacon started at $(date)" | tee $LOG_FILE
echo "[*] Target: $TARGET" | tee -a $LOG_FILE
echo "[*] Interval: ${INTERVAL} seconds" | tee -a $LOG_FILE
echo "[*] Press Ctrl+C to stop" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

COUNT=1
while true; do
    TIMESTAMP=$(date '+%H:%M:%S')
    
    # Send single ping
    ping -c 1 -W 1 $TARGET > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo "[$COUNT] $TIMESTAMP - Beacon sent successfully" | tee -a $LOG_FILE
    else
        echo "[$COUNT] $TIMESTAMP - Beacon failed" | tee -a $LOG_FILE
    fi
    
    ((COUNT++))
    sleep $INTERVAL
done
