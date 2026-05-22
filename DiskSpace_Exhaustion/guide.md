# Disk Space Exhaustion Attack

## Overview
**Disk Space Exhaustion** is a type of Denial of Service (DoS) attack where an attacker intentionally fills up available storage space on a target system. By writing massive amounts of junk data to critical directories (like `/tmp` and `/var`), the attacker prevents the operating system and running applications from functioning correctly.

---

## Attacker's Gain
- **Denial of Service (DoS)**: Critical system services, web servers, and databases will crash or freeze when they are unable to create temporary files or write session data.
- **Log Evasion**: By filling up the partition where logs are stored (often under `/var`), the attacker forces logging services (like `syslog` or `journald`) to drop logs. This hides traces of further malicious activities.
- **System Instability**: If the primary partition is filled to 100%, the entire operating system may become unstable, sometimes preventing strict administrators from logging in or executing basic commands.
- **Disabling Defenses**: Security tools, EDRs, and antivirus engines that need to unpack files or write to disk to scan them will fail if there is no space left.

---

## How the Attack Works
The attack leverages the built-in Unix `dd` utility to rapidly generate massive dummy files silently in the background:
1. **`dd`**: A command-line utility used to convert and copy files, frequently used for raw data manipulation.
2. **`if=/dev/zero`**: Uses the special `/dev/zero` block device as the input, which provides an infinite stream of null characters (zeros).
3. **`of=/tmp/fill.tmp`**: Defines the output file destination where the zeros will be continuously written.
4. **`bs=10M count=5000`**: Defines the target size. It writes chunks of 10 Megabytes (`bs`) exactly 5,000 times (`count`), attempting to create a ~50 Gigabyte file.
5. **`&`**: Sends the writing process to the background, allowing the attacker to regain control of the terminal while the disk silently hits maximum capacity.

---

## Disk Exhaustion Command

This script runs two simultaneous filler processes in the background, aggressively targeting both the `/tmp` and `/var` directories.

```bash
# Fill /tmp with ~50GB of null bytes
dd if=/dev/zero of=/tmp/fill.tmp bs=10M count=5000 status=progress 2>/dev/null &

# Fill /var/tmp with ~30GB of null bytes
dd if=/dev/zero of=/var/tmp/fill2.tmp bs=10M count=3000 status=progress 2>/dev/null &

echo "[+] Disk filler processes launched"
```

---

## ⚠️ Important Notes
- **Test Environments Only**: Running this in a production environment will likely cause immediate outages and data corruption for services attempting to write state.
- **Cleanup**: To stop the attack and recover space, you must terminate the running `dd` background processes (e.g., `killall dd` or `pkill dd`) and delete the generated junk payload files (`rm -f /tmp/fill.tmp /var/tmp/fill2.tmp`).
- **Defenses**: Administrators should enforce user disk quotas, mount `/tmp` and `/var` on separate isolated partitions, and employ storage monitoring alerts to mitigate this threat.