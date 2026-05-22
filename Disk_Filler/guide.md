# Disk Filler Attack

## Overview
The **Disk Filler** attack is a basic form of a Denial of Service (DoS) technique focused entirely on consuming the available storage capacity of a targeted partition (commonly `/tmp` or system partitions). By generating large amounts of useless data rapidly, it aims to suffocate processes that require disk space to operate correctly.

---

## Attacker's Gain
- **Service Outage**: Many applications, databases, and continuous integration pipelines require temporary disk space to execute efficiently. Filling the disk causes these applications to throw `No space left on device` errors and abruptly stop.
- **Hindering System Administrators**: A completely full filesystem usually prevents administrators from installing mitigation patches, archiving, or sometimes even performing basic text-editing via SSH to fix issues.
- **Log Dropping**: Filling the root (`/`) or `/var` partition can force critical logging programs to drop messages, causing the attacker's later actions to remain unrecorded.

---

## How the Attack Works
1. **`dd` utility**: This is standard Unix software designed to perform low-level data copying.
2. **`if=/dev/zero`**: This serves as an infinite stream of empty characters (null bytes).
3. **`of=/tmp/fill.bin`**: This writes the null bytes consecutively into a file named `fill.bin` situated in `/tmp`.
4. **`bs=50M count=80`**: The command writes in Block Sizes (`bs`) of 50 Megabytes, repeating exactly 80 times (`count`). This produces a single `~4 Gigabyte` file.
5. **`&` and `status=progress`**: The `&` symbol forces the intensive write cycle into the background, letting the attacker queue up other commands immediately, while `status=progress` periodically echoes the byte-write speed and progress to the visible console.

---

## Disk Filler Command

This snippet generates a 4GB dummy file softly in the background.

```bash
# Disk Filler using dd

dd if=/dev/zero of=/tmp/fill.bin bs=50M count=80 status=progress &
```

---

## ⚠️ Important Notes
- **Testing & Safety**: Ensure your test system has more space than the scripted threshold (e.g., 4GB), or adjust testing parameters accordingly. It will max out storage rapidly if modified to larger values.
- **Recovery Strategy**: The attack is mitigated easily by killing the active `dd` job (`pkill dd`) and permanently deleting the targeted dummy file (`rm /tmp/fill.bin`).
- **Defensive Solutions**: Implement strict file-system directory quotas, isolate sensitive partitions, and utilize real-time alert monitors mapping to system disk capacity crossing 85-90% utilization.