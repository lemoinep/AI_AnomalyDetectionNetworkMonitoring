# Author(s): Dr. Patrick Lemoine + VPX AI Assistant
# Network/Bluetooth monitoring, advanced detection with AI + adaptive standby
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

# IA/ML
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

MALICIOUS_IPS_FILE = "malicious_ips.json"
SUSPICIOUS_FILES_LOG = "suspicious_files.json"
PATTERNS_FILE = "ia_threat_patterns.json"
ML_MODEL_PATH = "malware_rf_model.pkl"

# Ports critiques typiques malware IA évolutif
CRITICAL_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 445: "SMB",
    3389: "RDP", 4444: "Metasploit Shell", 6660: "IRC Malware", 8333: "Bitcoin Mining",
    50000: "High suspicious port", 8080: "HTTP Proxy"
}

AUTHORIZED_BLUETOOTH_MACS = set()

def load_patterns(file=PATTERNS_FILE):
    try:
        with open(file, "r") as f:
            patt = json.load(f)
            print(f"[ThreatIntel] Patterns IA chargés ({len(patt)} patterns).")
            return set(patt)
    except Exception as e:
        print(f"[ThreatIntel] Erreur chargement patterns: {e}")
        # fallback = patterns basiques
        return {"python*", "powershell*", "wscript*", "svchost.exe", "meterpreter", "malware*", "shell*", "randomized_exe"}

SUSPICIOUS_PROCESS_PATTERNS = load_patterns()

def load_ml_model(path=ML_MODEL_PATH):
    try:
        model = joblib.load(path)
        print("[ML] Modèle Random Forest chargé avec succès.")
        return model
    except Exception as e:
        print(f"[ML] Erreur au chargement du modèle: {e}")
        return None

ml_model = load_ml_model()

def extract_conn_features(conn):
    """Retourne les features au format numpy array pour le modèle ML"""
    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        port = 0
    critical_port = int(port in CRITICAL_PORTS)
    high_port = int(port > 50000)
    proc_len = len(conn['process']) if 'process' in conn else 0
    suspicious_proc = int(any(conn['process'].lower().startswith(p.replace("*", "")) for p in SUSPICIOUS_PROCESS_PATTERNS))
    # Ajoute tes autres features ici si besoin
    return np.array([port, critical_port, high_port, proc_len, suspicious_proc]).reshape(1, -1)

def ml_suspicion_score(conn):
    if not ml_model:
        return 0
    features = extract_conn_features(conn)
    proba = ml_model.predict_proba(features)[0][1]  # probabilité de malware
    return proba

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

def get_connections():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            try:
                proc = psutil.Process(c.pid)
                pname = proc.name()
                exe_path = proc.exe() if proc and proc.exe() else ""
            except Exception:
                pname = "N/A"
                exe_path = ""
            conns.append({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'laddr': f"{c.laddr.ip}:{c.laddr.port}",
                'raddr': f"{c.raddr.ip}:{c.raddr.port}",
                'status': c.status,
                'pid': c.pid,
                'process': pname,
                'exe_path': exe_path
            })
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
        alerts.append(f"Connexion port critique {port} ({CRITICAL_PORTS[port]})")
        add_ip = True
    if remote_ip in malicious_ips:
        alerts.append("IP malveillante connue")
    if conn['process'] in ['explorer.exe', 'svchost.exe'] and port > 1024:
        alerts.append("Process système sur port non privilégié")
        add_ip = True
    if port == 53 and conn['process'] not in ['dnsmasq', 'named', 'systemd-resolved']:
        alerts.append("Trafic DNS inhabituel")
        add_ip = True
    proc_name = conn['process'].lower()
    for pattern in SUSPICIOUS_PROCESS_PATTERNS:
        if proc_name.startswith(pattern.replace("*", "")):
            alerts.append(f"Process suspect pattern IA : {proc_name}")
            add_ip = True
    if port > 50000:
        alerts.append("Port très élevé suspect")
        add_ip = True
    if 'exe_path' in conn and conn['exe_path'] and not any(conn['exe_path'].startswith(path) for path in ["C:\\Windows\\System32", "/usr/bin/", "/bin/"]):
        alerts.append(f"Exécution chemin inhabituel : {conn['exe_path']}")
        log_suspicious_file(conn['exe_path'], conn['process'])
        add_ip = True

    if add_ip and remote_ip not in malicious_ips and remote_ip != "0.0.0.0":
        return alerts, remote_ip
    return alerts, None

def scan_bluetooth_devices():
    try:
        print("[Bluetooth] Scanning for Bluetooth devices...")
        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        print(f"[Bluetooth] Found {len(nearby_devices)} device(s).")
        return nearby_devices
    except Exception as e:
        print(f"[Bluetooth] Error during scan: {e}")
        return []

def detect_bluetooth_intrusion(devices):
    alerts = []
    for addr, name in devices:
        if addr not in AUTHORIZED_BLUETOOTH_MACS:
            alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def block_internet():
    system = platform.system()
    print("[Network] Blocking internet access due to intrusion detection!")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        os.system('nmcli radio wifi off')
    else:
        print("[Network] Blocking not implemented for this OS.")

def unblock_internet():
    system = platform.system()
    print("[Network] Re-enabling internet access.")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=enable')
    elif system == "Linux":
        os.system('nmcli radio wifi on')
    else:
        print("[Network] Unblocking not implemented for this OS.")

def block_bluetooth():
    system = platform.system()
    print("[Bluetooth] Blocking Bluetooth interface!")
    if system == "Linux":
        os.system('rfkill block bluetooth')
    elif system == "Windows":
        print("[Bluetooth] Manual Bluetooth deactivation required on Windows.")
    else:
        print("[Bluetooth] Bluetooth blocking not implemented for this OS.")

def load_authorized_bluetooth_macs(filename="authorized_bluetooth_macs.json"):
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def main():
    report = []
    malicious_ips = load_malicious_ips()
    internet_blocked = False
    bluetooth_blocked = False
    AUTHORIZED_BLUETOOTH_MACS = load_authorized_bluetooth_macs()
    # charge patterns dyn/veille
    global SUSPICIOUS_PROCESS_PATTERNS
    SUSPICIOUS_PROCESS_PATTERNS = load_patterns()

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
                print(f"ALERT: {alert_msg} - Connexion: {conn}")
                conn['ALERT'] = alert_msg
                intrusion_detected = True
                if new_ip:
                    malicious_ips.add(new_ip)
                    updated = True
                    print(f"Nouvelle IP ajoutée à la blacklist: {new_ip}")
            else:
                conn['ALERT'] = ''
            report.append(conn)
        if updated:
            save_malicious_ips(malicious_ips)
        if report:
            df = pd.DataFrame(report)
            df.to_csv("network_report.csv", index=False)
        report.clear()
        if intrusion_detected and not internet_blocked:
            block_internet()
            internet_blocked = True

        bt_devices = scan_bluetooth_devices()
        bt_alerts = detect_bluetooth_intrusion(bt_devices)
        if bt_alerts and not bluetooth_blocked:
            for alert in bt_alerts:
                print(f"ALERT: {alert}")
            block_bluetooth()
            bluetooth_blocked = True

        time.sleep(60)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        authorized_macs = build_bluetooth_macs()
        save_bluetooth_macs(authorized_macs)
        print("Bluetooth MACs saved! You can now run in surveillance mode.")
    else:
        main()
