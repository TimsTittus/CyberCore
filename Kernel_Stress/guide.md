# Kernel Stress / Memory Pressure Attack

## Overview
**Kernel Stress** (or Memory/I/O Pressure simulation) is a Denial of Service (DoS) technique that deliberately forces the operating system's kernel to work extremely hard by creating simultaneous, massive inputs and outputs (I/O). It mimics chaotic system load and memory manipulation, heavily taxing the CPU and the kernel's memory management subsystem.

---

## Attacker's Gain
- **System Unresponsiveness**: High I/O and rapid consumption of memory allocation buffers throttle legitimate background processes.
- **Service Disruption**: Time-sensitive applications and databases (which rely heavily on cache) might slow down, drop connections, or crash entirely.
- **Kernel Panic Simulation**: Severe memory and cache manipulation can occasionally lead a vulnerable or unpatched kernel to lock up entirely, mimicking a Kernel Panic.
- **Evading Detection temporarily**: Creating massive noise and load on the kernel can sometimes lag logging servers, SIEM agents, or EDR systems, making it difficult for them to send alerts in real-time.

---

## How the Attack Works
1. **The Loop**: A `for` loop is spawned `50` times.
2. **Reading `/dev/urandom`**: `/dev/urandom` is a pseudo-random number generator in Unix. Reading from it requires CPU cycles to generate the cryptographic randomness.
3. **Writing to `/tmp`**: Using `head -c 100M`, the script pulls 100 Megabytes of random data per loop and writes it directly to disk (`/tmp/stress1.tmp`, `/stress2.tmp`, etc.). 
4. **Background Execution**: Each read/write job is sent to the background (`&`), meaning 50 heavy I/O operations and CPU generators happen concurrently.
5. **Dropping Caches**: The command `echo 1 > /proc/sys/vm/drop_caches` forces the Linux kernel to immediately drop all pagecache. This aggressively unloads previously cached files from RAM, forcing the kernel to re-read everything from the disk when normally requested, creating further severe I/O bottlenecks.

---

## Kernel Stress Command

*Warning: This requires `root` privileges to drop caches successfully, though the `/dev/urandom` spam will work as a standard user.*

```bash
# Spawn 50 parallel jobs generating highly randomized 100MB files
for i in {1..50}; do
    cat /dev/urandom | head -c 100M > /tmp/stress$i.tmp &
done

# Attempt to clear kernel pagecache to maximize I/O pressure
echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true

echo "[+] Kernel memory pressure applied"
```

---

## ⚠️ Important Notes
- **Testing Use Only**: Do not use on production systems. This will immediately cause extreme latency across the OS for both SSH sessions and application hosting.
- **Cleanup / Recovery**: Admins should terminate the background processes handling the data generation (e.g., `killall cat` and `killall head`) and wipe the temporary files from the `/tmp` directory (`rm -f /tmp/stress*.tmp`) to free space and reduce I/O backlog.
- **Defense Mechanisms**: Defense against this requires proper utilization of `cgroups`, IOPS limitations on user quotas, and aggressive alerting on abnormally high CPU wait states (`iowait`).