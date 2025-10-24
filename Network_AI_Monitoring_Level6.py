# Author(s): Dr. Patrick Lemoine + VPX AI Assistant
# Network/Bluetooth monitoring and AI-based advanced intrusion detection
# Preparation and development of a barrier against artificial intelligence viruses.
# Remark it is only a draft for instance. 

import psutil
import pandas as pd
import time
from datetime import datetime
import json
import hashlib
import os
import platform
import bluetooth
import sys
import threading
import logging
import math
from collections import defaultdict, deque

# AI/ML
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

MALICIOUS_IPS_FILE = "malicious_ips.json"
SUSPICIOUS_FILES_LOG = "suspicious_files.json"
PATTERNS_FILE = "ia_threat_patterns.json"
ML_MODEL_PATH = "malware_rf_model.pkl"
EVENT_LOG = "system_monitor.log"

# Critical ports typically abused by evolving AI malware
CRITICAL_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 445: "SMB",
    3389: "RDP", 4444: "Metasploit Shell", 6660: "IRC Malware", 8333: "Bitcoin Mining",
    50000: "High suspicious port", 8080: "HTTP Proxy"
}
AUTHORIZED_BLUETOOTH_MACS = set()

# Detailed logging: everything goes to a file and also to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(EVENT_LOG, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

# For enriched ML features
CONN_HISTORY = defaultdict(lambda: deque(maxlen=20)) # Keeps 20 recent connections per IP for statistics
CONN_START_TIMES = {}  # pid <-> start time

def entropy(s):
    """Calculate Shannon entropy of a string (for process name obfuscation detection)."""
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob if p > 0]) if s else 0

def load_patterns(file=PATTERNS_FILE):
    try:
        with open(file, "r") as f:
            patts = json.load(f)
            logging.info(f"[ThreatIntel] Loaded AI patterns ({len(patts)} patterns).")
            return set(patts)
    except Exception as e:
        logging.warning(f"[ThreatIntel] Error loading patterns: {e}")
        return {"python*", "powershell*", "wscript*", "svchost.exe", "meterpreter", "malware*", "shell*", "randomized_exe"}

def load_ml_model(path=ML_MODEL_PATH):
    try:
        model = joblib.load(path)
        logging.info("[ML] Random Forest model loaded successfully.")
        return model
    except Exception as e:
        logging.error(f"[ML] Error loading model: {e}")
        return None

def get_sha256(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def log_suspicious_file(filepath, process_name):
    sha = get_sha256(filepath)
    if not sha:
        return
    entry = {"timestamp": datetime.now().isoformat(), "file": filepath, "process": process_name, "sha256": sha}
    try:
        if os.path.isfile(SUSPICIOUS_FILES_LOG):
            with open(SUSPICIOUS_FILES_LOG, "r") as f:
                data = json.load(f)
        else:
            data = []
        data.append(entry)
        with open(SUSPICIOUS_FILES_LOG, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

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

def load_authorized_bluetooth_macs(filename="authorized_bluetooth_macs.json"):
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

# Enriched ML features: port, critical port, high port, process length, suspicious process,
# connection duration, frequency to the IP, and entropy of process name.
def extract_conn_features(conn):
    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        port = 0
        remote_ip = ""
    process = conn.get('process', '')
    # Duration
    start_time = CONN_START_TIMES.get(conn.get('pid'), time.time())
    duration = time.time() - start_time
    # Frequency: times this remote IP seen in last 20 connections
    ip_hist = CONN_HISTORY[remote_ip]
    freq = len(ip_hist) / 20.0  # ratio in last 20
    # Entropy of process name
    entropy_proc = entropy(process)
    # Copied from user original plus added features
    critical_port = int(port in CRITICAL_PORTS)
    high_port = int(port > 50000)
    proc_len = len(process)
    suspicious_proc = int(any(process.lower().startswith(p.replace("*", "")) for p in SUSPICIOUS_PROCESS_PATTERNS))
    return np.array([port, critical_port, high_port, proc_len, suspicious_proc, duration, freq, entropy_proc]).reshape(1,-1)

def track_process_start(conn):
    pid = conn.get('pid')
    if pid not in CONN_START_TIMES:
        try:
            p = psutil.Process(pid)
            CONN_START_TIMES[pid] = p.create_time()
        except Exception:
            CONN_START_TIMES[pid] = time.time()

def get_connections():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            try:
                proc = psutil.Process(c.pid)
                pname = proc.name()
                exe_path = proc.exe() if proc and proc.exe() else ""
                start_time = proc.create_time()
            except Exception:
                pname = "N/A"
                exe_path = ""
                start_time = time.time()
            entry = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'laddr': f"{c.laddr.ip}:{c.laddr.port}",
                'raddr': f"{c.raddr.ip}:{c.raddr.port}",
                'status': c.status,
                'pid': c.pid,
                'process': pname,
                'exe_path': exe_path
            }
            conns.append(entry)
            track_process_start(entry)
            CONN_HISTORY[entry['raddr']].append(entry['pid'])
    return conns

def detect_advanced_intrusion(conn, malicious_ips):
    alerts = []
    add_ip = False
    remote_ip, port = "0.0.0.0", 0
    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        pass

    if port in CRITICAL_PORTS:
        alerts.append(f"Critical port connection {port} ({CRITICAL_PORTS[port]})")
        add_ip = True
    if remote_ip in malicious_ips:
        alerts.append("IP known malicious")
    if conn['process'] in ['explorer.exe', 'svchost.exe'] and port > 1024:
        alerts.append("System process on unprivileged port")
        add_ip = True
    if port == 53 and conn['process'] not in ['dnsmasq', 'named', 'systemd-resolved']:
        alerts.append("Unusual DNS traffic")
        add_ip = True
    proc_name = conn['process'].lower()
    for pattern in SUSPICIOUS_PROCESS_PATTERNS:
        if proc_name.startswith(pattern.replace("*", "")):
            alerts.append(f"Suspicious process pattern AI: {proc_name}")
            add_ip = True
    if port > 50000:
        alerts.append("Very high suspicious port")
        add_ip = True
    if 'exe_path' in conn and conn['exe_path'] and not any(
        conn['exe_path'].startswith(path) for path in ["C:\\Windows\\System32", "/usr/bin/", "/bin/"]):
        alerts.append(f"Execution in unusual path: {conn['exe_path']}")
        log_suspicious_file(conn['exe_path'], conn['process'])
        add_ip = True

    if add_ip and remote_ip not in malicious_ips and remote_ip != "0.0.0.0":
        return alerts, remote_ip
    return alerts, None

def scan_bluetooth_devices():
    try:
        logging.info("[Bluetooth] Scanning for Bluetooth devices...")
        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        logging.info(f"[Bluetooth] Found {len(nearby_devices)} device(s).")
        return nearby_devices
    except Exception as e:
        logging.error(f"[Bluetooth] Error during scan: {e}")
        return []

def detect_bluetooth_intrusion(devices):
    alerts = []
    for addr, name in devices:
        if addr not in AUTHORIZED_BLUETOOTH_MACS:
            alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def block_internet():
    system = platform.system()
    logging.warning("[Network] Blocking internet access due to intrusion detection!")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        os.system('nmcli radio wifi off')
    elif system == "Darwin":
        os.system('networksetup -setairportpower en0 off')
    else:
        logging.warning("[Network] Blocking not implemented for this OS.")

def unblock_internet():
    system = platform.system()
    logging.info("[Network] Re-enabling internet access.")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=enable')
    elif system == "Linux":
        os.system('nmcli radio wifi on')
    elif system == "Darwin":
        os.system('networksetup -setairportpower en0 on')
    else:
        logging.info("[Network] Unblocking not implemented for this OS.")

def block_bluetooth():
    system = platform.system()
    logging.warning("[Bluetooth] Blocking Bluetooth interface!")
    if system == "Linux":
        os.system('rfkill block bluetooth')
    elif system == "Windows":
        logging.warning("[Bluetooth] Manual Bluetooth deactivation required on Windows.")
    elif system == "Darwin":
        os.system('sudo defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0; sudo killall -HUP blued')
    else:
        logging.warning("[Bluetooth] Bluetooth blocking not implemented for this OS.")

def network_monitor(malicious_ips):
    internet_blocked = False
    while True:
        conns = get_connections()
        updated = False
        intrusion_detected = False
        for conn in conns:
            alerts, new_ip = detect_advanced_intrusion(conn, malicious_ips)
            ml_score = ml_suspicion_score(conn)
            if alerts or ml_score > 0.7:
                alert_msg = " | ".join(alerts)
                if ml_score > 0.7:
                    alert_msg += f" [ML suspicion score: {ml_score:.2f}]"
                logging.warning(f"ALERT: {alert_msg} - Connection: {conn}")
                conn['ALERT'] = alert_msg
                intrusion_detected = True
                if new_ip:
                    malicious_ips.add(new_ip)
                    updated = True
                    logging.info(f"New IP added to the blacklist: {new_ip}")
            else:
                conn['ALERT'] = ''
        if updated:
            save_malicious_ips(malicious_ips)
        if intrusion_detected and not internet_blocked:
            block_internet()
            internet_blocked = True
        time.sleep(30)  # check more frequently

def bluetooth_monitor():
    bluetooth_blocked = False
    global AUTHORIZED_BLUETOOTH_MACS
    AUTHORIZED_BLUETOOTH_MACS = load_authorized_bluetooth_macs()
    while True:
        bt_devices = scan_bluetooth_devices()
        bt_alerts = detect_bluetooth_intrusion(bt_devices)
        if bt_alerts and not bluetooth_blocked:
            for alert in bt_alerts:
                logging.warning(f"ALERT: {alert}")
            block_bluetooth()
            bluetooth_blocked = True
        time.sleep(60)

def ml_suspicion_score(conn):
    if not ml_model:
        return 0
    features = extract_conn_features(conn)
    proba = ml_model.predict_proba(features)[0][1]
    return proba

def main():
    global SUSPICIOUS_PROCESS_PATTERNS
    SUSPICIOUS_PROCESS_PATTERNS = load_patterns()
    global ml_model
    ml_model = load_ml_model()
    malicious_ips = load_malicious_ips()

    net_thread = threading.Thread(target=network_monitor, args=(malicious_ips,), daemon=True)
    bt_thread = threading.Thread(target=bluetooth_monitor, daemon=True)
    net_thread.start()
    bt_thread.start()
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Shutdown requested by user.")

def build_bluetooth_macs():
    """
    Prompts user to scan for Bluetooth devices and select authorized MAC addresses.
    Returns a set of selected MAC addresses.
    """
    print("Scanning for Bluetooth devices to build the authorized list...")
    devices = scan_bluetooth_devices()
    if not devices:
        print("No Bluetooth devices found.")
        return set()
    authorized = set()
    for idx, (addr, name) in enumerate(devices):
        print(f"[{idx}] {name} ({addr})")
    selection = input("Enter the numbers for the devices you want to authorize, separated by commas (e.g., 0,2): ")
    try:
        indices = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
        for i in indices:
            if 0 <= i < len(devices):
                authorized.add(devices[i][0])
    except Exception as e:
        print(f"Error in selection: {e}")
    print(f"Authorized MAC addresses: {authorized}")
    return authorized

def save_bluetooth_macs(mac_set, filename="authorized_bluetooth_macs.json"):
    """
    Saves the authorized MAC address set to a JSON file.
    """
    try:
        with open(filename, "w") as f:
            json.dump(sorted(list(mac_set)), f, indent=2)
        print(f"Authorized MACs saved to {filename}")
    except Exception as e:
        print(f"Error saving authorized MACs: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        authorized_macs = build_bluetooth_macs()
        save_bluetooth_macs(authorized_macs)
        print("Bluetooth MACs saved! You can now run in surveillance mode.")
    else:
        main()
