# Memory Exhaustion Attack (Resource Exhaustion)

## Overview
**Memory/Resource Exhaustion** is a type of Denial of Service (DoS) attack designed to consume the target system's available memory (RAM) or process space constraints (like process IDs). The goal is to leave no system resources available for legitimate applications or the operating system itself to function properly, often rendering the system entirely unresponsive.

Unlike a pure CPU-bound loop, memory exhaustion relies on aggressive allocation of state, buffers, or process copies (forking). In this specific script variation, it behaves somewhat like a slow fork bomb mixed with a background runaway process.

---

## Attacker's Gain

- **Denial of Service (DoS)**: Forces the system to slow down to a crawl, eventually triggering the OOM (Out Of Memory) killer, which may terminate critical services or crash the system completely.
- **Service Disruption**: Application servers, databases, and network listeners drop connections or fail to handle incoming user requests because the OS refuses to allocate any more memory.
- **Distraction & Chaos**: Used as a smoke-screen or a distraction during another attack. Security teams spend time diagnosing a system freeze while the attacker quietly exfiltrates data elsewhere.
- **Exploiting Weak Configurations**: Proves that the system lacks process and memory limits (like `cgroups` or user `ulimit` restrictions), verifying system instability.

---

## How the Attack Works
1. The attacker runs a small embedded Python script in the background.
2. The script continuously loops `300` times. Within each loop, it calls `os.fork()`.
3. `os.fork()` copies the current Python process exactly as-is into memory. This allocates memory for a new process each time.
4. The `time.sleep(0.01)` spaces out the execution slightly. This helps bypass very simplistic, burst rate-based anomaly detection systems and gives the OS just enough time to process the forks without tripping immediate safeguards.
5. All output and errors (`> /dev/null 2>&1`) are muted, ensuring it runs completely silently in the background (`&`), leaving the user or admin unaware of why the system is slowing down.

---

## Memory Exhaustion Command

This payload runs natively on systems with Python 3 installed. It's meant to quietly and aggressively consume process resources in the background.

```bash
# Execute a silent background process to continuously fork Python
python3 -c "
import os, time
for _ in range(300):
    try:
        os.fork()
    except:
        pass
    time.sleep(0.01)
print('[+] Memory/Process exhaustion started')
" > /dev/null 2>&1 &
```

---

## ⚠️ Important Notes
- **Testing Environment Only**: Running this in a production environment can crash servers or disrupt critical applications.
- **Mitigation / Defense**: Protect systems against this by correctly setting limits via `/etc/security/limits.conf` (e.g., `nproc`, `as`), employing properly tuned Docker/container `cgroups`, or utilizing `systemd` resource constraints.
- **Recovery**: If a system falls victim to this, recovering it without a hard power reboot can be exceedingly difficult because even standard tools like `kill` or `ps` may fail to launch due to exhaustion.