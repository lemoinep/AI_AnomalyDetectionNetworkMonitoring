# Author(s): Dr. Patrick Lemoine

# GOAL :
# This program provides advanced, AI-powered monitoring of both network and 
# Bluetooth activity on a computer system. It continuously analyzes network connections 
# using machine learning models to detect anomalies, suspicious ports, and
# known malicious IP addresses. The script also scans for nearby Bluetooth devices, 
# alerting and blocking the interface if unauthorized devices are detected. 
# When a threat is identified, the program can automatically block internet or 
# Bluetooth access to protect the system. All detected events and connection details 
# are logged into a CSV report for later review. 
# This comprehensive approach helps automate incident response and 
# enhances system security through intelligent surveillance

import os
import time
import psutil
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from datetime import datetime
import platform
import bluetooth
import json
import joblib
from sklearn.ensemble import IsolationForest

# --- FILES ---
MODEL_FILE_SK = "network_ai_model.pkl"
MODEL_FILE_LSTM = "network_lstm_model.h5"
REPORT_FILE = "network_ai_report.csv"
MALICIOUS_IPS_FILE = "malicious_ips.json"
AUTHORIZED_BLUETOOTH_MACS_FILE = "authorized_bluetooth_macs.json"
WINDOW_SIZE = 10
RETRAIN_INTERVAL = 60 * 60

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

# ------------------ Bluetooth Management ------------------

def build_authorized_bluetooth_macs():
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
    with open(filename, "w") as f:
        json.dump(sorted(list(mac_set)), f, indent=2)
    print(f"Saved {len(mac_set)} authorized Bluetooth MAC addresses to {filename}")

def load_authorized_bluetooth_macs(filename=AUTHORIZED_BLUETOOTH_MACS_FILE):
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def scan_bluetooth_devices():
    try:
        print("[Bluetooth] Scanning for Bluetooth devices...")
        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        print(f"[Bluetooth] Found {len(nearby_devices)} device(s).")
        return nearby_devices
    except Exception as e:
        print(f"[Bluetooth] Error during scan: {e}")
        return []

def detect_bluetooth_intrusion(devices, authorized_macs):
    alerts = []
    for addr, name in devices:
        if addr not in authorized_macs:
            alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def block_bluetooth():
    system = platform.system()
    print("[Bluetooth] Blocking Bluetooth interface!")
    if system == "Linux":
        os.system('rfkill block bluetooth')
    elif system == "Windows":
        print("[Bluetooth] Manual Bluetooth deactivation required on Windows.")
    else:
        print("[Bluetooth] Bluetooth blocking not implemented for this OS.")

# ------------------ Network Management ------------------

def load_malicious_ips():
    if not os.path.isfile(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, 'w') as f:
            json.dump([], f)
        return set()
    with open(MALICIOUS_IPS_FILE, 'r') as f:
        return set(json.load(f))

def save_malicious_ips(ips):
    with open(MALICIOUS_IPS_FILE, 'w') as f:
        json.dump(sorted(list(ips)), f, indent=2)

def block_internet():
    system = platform.system()
    print("Blocking internet access due to intrusion detection (AI)!")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        os.system('nmcli radio wifi off')
    else:
        print("Blocking not implemented for this OS.")

def extract_features(conn):
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

# ------------------ IsolationForest Model ------------------

def train_model(data):
    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(data)
    joblib.dump(model, MODEL_FILE_SK)
    print("AI IsolationForest model trained and saved.")

def load_or_train_model():
    if os.path.exists(MODEL_FILE_SK):
        model = joblib.load(MODEL_FILE_SK)
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
        model = joblib.load(MODEL_FILE_SK)
    return model

# ------------------ LSTM Model ------------------

def create_lstm_model(input_shape):
    model = keras.Sequential([
        keras.layers.LSTM(64, input_shape=input_shape, return_sequences=True),
        keras.layers.LSTM(32),
        keras.layers.Dense(16, activation='relu'),
        keras.layers.Dense(1)
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def train_lstm_model(X):
    X = np.array(X)
    X_seq = []
    for i in range(len(X) - WINDOW_SIZE):
        X_seq.append(X[i:i+WINDOW_SIZE])
    X_seq = np.array(X_seq)
    model = create_lstm_model((WINDOW_SIZE, X.shape[1]))
    model.fit(X_seq, X_seq[:, -1, :], epochs=10, batch_size=16, verbose=1)
    model.save(MODEL_FILE_LSTM)
    print("LSTM model trained and saved.")

def load_or_train_lstm_model():
    if os.path.exists(MODEL_FILE_LSTM):
        model = keras.models.load_model(MODEL_FILE_LSTM)
    else:
        print("Training LSTM model on initial traffic... Please wait 1 minute.")
        baseline = []
        start = time.time()
        while time.time() - start < 60:
            conns = get_connections()
            for conn in conns:
                baseline.append(extract_features(conn))
            time.sleep(2)
        train_lstm_model(baseline)
        model = keras.models.load_model(MODEL_FILE_LSTM)
    return model

# ------------------ Classic Intrusion Options ------------------

def ai_intrusion_options(conn, malicious_ips):
    alerts = []
    add_ip = False
    block = False
    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        remote_ip, port = "0.0.0.0", 0
    if port in CRITICAL_PORTS:
        alerts.append(f"Critical port detected: {port} ({CRITICAL_PORTS[port]})")
        add_ip = True
        block = True
    if remote_ip in malicious_ips:
        alerts.append("Known malicious IP")
        block = True
    suspicious_processes = {'nc', 'telnet', 'meterpreter'}
    if conn['process'].lower() in suspicious_processes:
        alerts.append(f"Suspicious process: {conn['process']}")
        add_ip = True
        block = True
    if port > 50000:
        alerts.append("Unusually high port")
        add_ip = True
    if add_ip and remote_ip not in malicious_ips and remote_ip != "0.0.0.0":
        return alerts, remote_ip, block
    return alerts, None, block

# ------------------ Main Surveillance Loop ------------------

def main(mode="isolationforest"):
    report = []
    malicious_ips = load_malicious_ips()
    if mode == "lstm":
        model = load_or_train_lstm_model()
        X_window = []
        last_retrain = time.time()
    else:
        model = load_or_train_model()
    internet_blocked = False
    bluetooth_blocked = False
    AUTHORIZED_BLUETOOTH_MACS = load_authorized_bluetooth_macs()
    print("AI-based network and Bluetooth monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            conns = get_connections()
            features = [extract_features(conn) for conn in conns]
            block_flag = False
            updated = False

            # --- AI Network Surveillance ---
            if features:
                if mode == "lstm":
                    X_window += features
                    if len(X_window) > WINDOW_SIZE:
                        X_window = X_window[-WINDOW_SIZE:]
                    if len(X_window) == WINDOW_SIZE:
                        X_pred = np.array([X_window])
                        pred = model.predict(X_pred, verbose=0)
                        mse = np.mean((X_pred[:, -1, :] - pred) ** 2)
                        if mse > 1000:  # Ajustez ce seuil!
                            print(f"LSTM ALERT: Anomalous network activity detected (MSE={mse:.2f})")
                            if not internet_blocked:
                                block_internet()
                                internet_blocked = True
                        # Ajout au rapport
                        for conn in conns:
                            conn['LSTM_ALERT'] = "YES" if internet_blocked else ""
                            report.append(conn)
                    # Retrain périodique
                    if time.time() - last_retrain > RETRAIN_INTERVAL:
                        print("Retraining LSTM model with recent data...")
                        retrain_data = []
                        for _ in range(100):
                            conns2 = get_connections()
                            for conn2 in conns2:
                                retrain_data.append(extract_features(conn2))
                            time.sleep(1)
                        train_lstm_model(retrain_data)
                        model = keras.models.load_model(MODEL_FILE_LSTM)
                        last_retrain = time.time()
                else:
                    preds = model.predict(features)
                    for conn, pred in zip(conns, preds):
                        if pred == -1:
                            conn['AI_ALERT'] = 'YES'
                            print(f"AI ALERT: Anomalous connection detected: {conn}")
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
                    if updated:
                        save_malicious_ips(malicious_ips)
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

            # --- Save Report ---
            if len(report) > 0:
                df = pd.DataFrame(report)
                df.to_csv(REPORT_FILE, index=False)
                report.clear()
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
        authorized_macs = build_authorized_bluetooth_macs()
        save_authorized_bluetooth_macs(authorized_macs)
        print("Bluetooth MACs saved! You can now run in surveillance mode.")
    elif len(sys.argv) > 1 and sys.argv[1] == "lstm":
        main(mode="lstm")
    else:
        main(mode="isolationforest")
