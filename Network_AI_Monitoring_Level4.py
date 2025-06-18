# Author(s): Dr. Patrick Lemoine
# ADD Bluetooth scanning
# Under construction, there will be lots of options afterwards.

import psutil
import pandas as pd
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import os
import json
import platform
import bluetooth  # PyBluez for Bluetooth scanning

MODEL_FILE = "network_ai_model.pkl"
REPORT_FILE = "network_ai_report.csv"
MALICIOUS_IPS_FILE = "malicious_ips.json"
AUTHORIZED_BLUETOOTH_MACS_FILE = "authorized_bluetooth_macs.json"

# List of critical/dangerous ports with their service names
CRITICAL_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    3389: "RDP",
    4444: "Metasploit Shell",
    6660: "IRC Malware",
    8333: "Bitcoin Mining",
    50000: "High suspicious port",
    8080: "HTTP Proxy"
}

# ------------------ Bluetooth Management Functions ------------------

def build_authorized_bluetooth_macs():
    """
    Scans for nearby Bluetooth devices, displays their MAC addresses and names,
    and lets the user select which ones to authorize.
    Returns a set of selected MAC addresses.
    """
    print("Scanning for nearby Bluetooth devices...")
    devices = bluetooth.discover_devices(duration=8, lookup_names=True)
    if not devices:
        print("No Bluetooth devices found.")
        return set()
    
    print("\nFound Bluetooth devices:")
    for idx, (addr, name) in enumerate(devices):
        print(f"{idx+1}. {name} ({addr})")
    
    print("\nEnter the numbers (comma-separated) of devices you want to authorize, or press Enter to skip:")
    user_input = input("Selection: ")
    authorized = set()
    if user_input.strip():
        try:
            indices = [int(i.strip())-1 for i in user_input.split(",")]
            for i in indices:
                if 0 <= i < len(devices):
                    authorized.add(devices[i][0])
        except Exception as e:
            print(f"Invalid input: {e}")
    print(f"\nAUTHORIZED_BLUETOOTH_MACS = {authorized}")
    return authorized

def save_authorized_bluetooth_macs(mac_set, filename=AUTHORIZED_BLUETOOTH_MACS_FILE):
    """Saves the set of authorized Bluetooth MAC addresses to a JSON file."""
    with open(filename, "w") as f:
        json.dump(sorted(list(mac_set)), f, indent=2)
    print(f"Saved {len(mac_set)} authorized Bluetooth MAC addresses to {filename}")

def load_authorized_bluetooth_macs(filename=AUTHORIZED_BLUETOOTH_MACS_FILE):
    """Loads the set of authorized Bluetooth MAC addresses from a JSON file."""
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def scan_bluetooth_devices():
    """
    Scans for nearby Bluetooth devices and returns a list of their addresses and names.
    """
    try:
        print("[Bluetooth] Scanning for Bluetooth devices...")
        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        print(f"[Bluetooth] Found {len(nearby_devices)} device(s).")
        return nearby_devices
    except Exception as e:
        print(f"[Bluetooth] Error during scan: {e}")
        return []

def detect_bluetooth_intrusion(devices, authorized_macs):
    """
    Checks scanned Bluetooth devices against the authorized list.
    Returns a list of alerts for unauthorized devices.
    """
    alerts = []
    for addr, name in devices:
        if addr not in authorized_macs:
            alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def block_bluetooth():
    """
    Disables the Bluetooth interface.
    Implemented for Linux only (using rfkill).
    """
    system = platform.system()
    print("[Bluetooth] Blocking Bluetooth interface!")
    if system == "Linux":
        os.system('rfkill block bluetooth')
    elif system == "Windows":
        print("[Bluetooth] Manual Bluetooth deactivation required on Windows.")
    else:
        print("[Bluetooth] Bluetooth blocking not implemented for this OS.")

# ------------------ Network AI Intrusion Detection Functions ------------------

def load_malicious_ips():
    """Load the blacklist of malicious IPs from a JSON file."""
    if not os.path.isfile(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, 'w') as f:
            json.dump([], f)
        return set()
    with open(MALICIOUS_IPS_FILE, 'r') as f:
        return set(json.load(f))

def save_malicious_ips(ips):
    """Save the updated set of malicious IPs back to the JSON file."""
    with open(MALICIOUS_IPS_FILE, 'w') as f:
        json.dump(sorted(list(ips)), f, indent=2)

def block_internet():
    """
    Disables the main network interface to block Internet access.
    Adjust interface names for your system if needed.
    """
    system = platform.system()
    print("Blocking internet access due to intrusion detection (AI)!")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        os.system('nmcli radio wifi off')
    else:
        print("Blocking not implemented for this OS.")

def extract_features(conn):
    """
    Extracts numerical features from a connection dictionary for AI analysis.
    """
    try:
        r_ip, r_port = conn['raddr'].split(':')
        l_ip, l_port = conn['laddr'].split(':')
        features = [
            int(l_port),
            int(r_port),
            conn['pid'] if conn['pid'] else -1,
            1 if conn['status'] == "ESTABLISHED" else 0
        ]
        return features
    except:
        return [0, 0, -1, 0]

def get_connections():
    """
    Collects current network connections with relevant info.
    """
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            try:
                proc = psutil.Process(c.pid)
                pname = proc.name()
            except Exception:
                pname = "N/A"
            conns.append({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'laddr': f"{c.laddr.ip}:{c.laddr.port}",
                'raddr': f"{c.raddr.ip}:{c.raddr.port}",
                'status': c.status,
                'pid': c.pid,
                'process': pname
            })
    return conns

def train_model(data):
    """
    Trains an IsolationForest model on the provided data and saves it.
    """
    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(data)
    joblib.dump(model, MODEL_FILE)
    print("AI model trained and saved.")

def load_or_train_model():
    """
    Loads the AI model if it exists, otherwise trains a new one.
    """
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
    else:
        print("Training AI model on initial traffic... Please wait 1 minute.")
        baseline = []
        start = time.time()
        while time.time() - start < 60:
            conns = get_connections()
            for conn in conns:
                baseline.append(extract_features(conn))
            time.sleep(2)
        train_model(baseline)
        model = joblib.load(MODEL_FILE)
    return model

def ai_intrusion_options(conn, malicious_ips):
    """
    Additional classic intrusion options for AI alerts:
    - Critical port detection
    - Blacklist check
    - Dynamic blacklist update
    Returns (alerts_list, ip_to_blacklist, block_flag)
    """
    alerts = []
    add_ip = False
    block = False

    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        remote_ip, port = "0.0.0.0", 0

    # Critical port alert
    if port in CRITICAL_PORTS:
        alerts.append(f"Critical port detected: {port} ({CRITICAL_PORTS[port]})")
        add_ip = True
        block = True

    # Blacklist IP alert
    if remote_ip in malicious_ips:
        alerts.append("Known malicious IP")
        block = True

    # Suspicious process names
    suspicious_processes = {'nc', 'telnet', 'meterpreter'}
    if conn['process'].lower() in suspicious_processes:
        alerts.append(f"Suspicious process: {conn['process']}")
        add_ip = True
        block = True

    # Unusually high port
    if port > 50000:
        alerts.append("Unusually high port")
        add_ip = True

    # Add to blacklist if needed
    if add_ip and remote_ip not in malicious_ips and remote_ip != "0.0.0.0":
        return alerts, remote_ip, block
    return alerts, None, block

# ------------------ Main Surveillance Loop ------------------

def main():
    report = []
    malicious_ips = load_malicious_ips()
    model = load_or_train_model()
    internet_blocked = False
    bluetooth_blocked = False

    # Load authorized Bluetooth MACs
    AUTHORIZED_BLUETOOTH_MACS = load_authorized_bluetooth_macs()

    print("AI-based network and Bluetooth monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            # --- Network Surveillance ---
            conns = get_connections()
            features = [extract_features(conn) for conn in conns]
            block_flag = False
            updated = False

            if features:
                preds = model.predict(features)
                for conn, pred in zip(conns, preds):
                    if pred == -1:
                        conn['AI_ALERT'] = 'YES'
                        print(f"AI ALERT: Anomalous connection detected: {conn}")
                        # Classic options for AI alert
                        alerts, new_ip, block = ai_intrusion_options(conn, malicious_ips)
                        if alerts:
                            conn['AI_ALERT_INFO'] = " | ".join(alerts)
                        else:
                            conn['AI_ALERT_INFO'] = ''
                        if new_ip:
                            malicious_ips.add(new_ip)
                            updated = True
                            print(f"New IP added to blacklist: {new_ip}")
                        if block:
                            block_flag = True
                    else:
                        conn['AI_ALERT'] = ''
                        conn['AI_ALERT_INFO'] = ''
                    report.append(conn)

                # Save report every minute
                if len(report) > 0:
                    df = pd.DataFrame(report)
                    df.to_csv(REPORT_FILE, index=False)
                    report.clear()
                if updated:
                    save_malicious_ips(malicious_ips)
                # Block internet if needed and not already blocked
                if block_flag and not internet_blocked:
                    block_internet()
                    internet_blocked = True

            # --- Bluetooth Surveillance ---
            bt_devices = scan_bluetooth_devices()
            bt_alerts = detect_bluetooth_intrusion(bt_devices, AUTHORIZED_BLUETOOTH_MACS)
            if bt_alerts and not bluetooth_blocked:
                for alert in bt_alerts:
                    print(f"ALERT: {alert}")
                block_bluetooth()
                bluetooth_blocked = True

            time.sleep(60)
    except KeyboardInterrupt:
        print("\nMonitoring stopped. Saving report...")
        if len(report) > 0:
            df = pd.DataFrame(report)
            df.to_csv(REPORT_FILE, index=False)
        print(f"Report saved to {REPORT_FILE}")



if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "setup_bluetooth":
        # Setup mode: build and save authorized MACs
        authorized_macs = build_authorized_bluetooth_macs()
        save_authorized_bluetooth_macs(authorized_macs)
        print("Bluetooth MACs saved! You can now run in surveillance mode.")
    else:
        main()
