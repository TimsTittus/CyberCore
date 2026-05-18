# ICMP Beaconing

This document outlines the steps for performing and monitoring ICMP beaconing attacks.

---

## Normal Beacon Attack

1. Create the Beacon script:
   ```bash
   nano icmp_beacon.sh
   ```

2. Save and make the script executable:
   ```bash
   chmod +x icmp_beacon.sh
   ```

3. Run the Beacon script:
   ```bash
   ./icmp_beacon.sh
   ```

4. Let it run for about 2-3 minutes (you'll see approximately 24-36 beacons), then press `Ctrl+C` to stop.

5. Check the log file:
   ```bash
   cat /tmp/icmp_beacon.log
   ```

---

## Enhanced Beacon Attack

1. Create the Enhanced Beacon script:
   ```bash
   nano icmp_enhanced_beacon.sh
   ```

2. Save and make the script executable:
   ```bash
   chmod +x icmp_enhanced_beacon.sh
   ```

3. Run the Enhanced Beacon script:
   ```bash
   ./icmp_enhanced_beacon.sh
   ```

4. Detailed logs will be created as the script runs.

5. The script creates a dedicated directory and three separate log files:
   - **Main Log**: `/tmp/icmp_beacon/beacon.log` (The most critical log file)
   - **Exfiltrated Data Log**: `/tmp/icmp_beacon/exfiltrated_data.log`
   - **Error Log**: `/tmp/icmp_beacon/errors.log`

6. Management and monitoring commands:

   - **View the main log (live):**
     ```bash
     tail -f /tmp/icmp_beacon/beacon.log
     ```
   - **View the last 50 lines:**
     ```bash
     tail -n 50 /tmp/icmp_beacon/beacon.log
     ```
   - **Check exfiltrated data:**
     ```bash
     cat /tmp/icmp_beacon/exfiltrated_data.log
     ```
   - **See all log files:**
     ```bash
     ls -l /tmp/icmp_beacon/
     ```

---

## Notes
- Ensure you have the necessary permissions and authorization to perform these simulations.
- ICMP traffic may be restricted or monitored by network security devices. Always conduct tests in a controlled and legal environment.