# Author(s): Dr. Patrick Lemoine

import psutil
import pandas as pd
import time
from datetime import datetime
import json
import os
import platform

# File for storing the blacklist of malicious IPs
MALICIOUS_IPS_FILE = "malicious_ips.json"

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

def load_malicious_ips():
    """
    Load the blacklist of malicious IPs from a JSON file.
    If the file does not exist, create an empty one.
    Returns a set of blacklisted IPs.
    """
    if not os.path.isfile(MALICIOUS_IPS_FILE):
        with open(MALICIOUS_IPS_FILE, 'w') as f:
            json.dump([], f)
        return set()
    with open(MALICIOUS_IPS_FILE, 'r') as f:
        return set(json.load(f))

def save_malicious_ips(ips):
    """
    Save the updated set of malicious IPs back to the JSON file.
    """
    with open(MALICIOUS_IPS_FILE, 'w') as f:
        json.dump(sorted(list(ips)), f, indent=2)

def get_connections():
    """
    Retrieve a list of current active network connections.
    For each connection, gather information such as timestamp, local and remote addresses,
    status, process ID, and process name.
    Only include connections that have a remote address (i.e., established connections).
    """
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:  # Only consider connections with a remote address
            try:
                proc = psutil.Process(c.pid)  # Get the process object by PID
                pname = proc.name()           # Get the process name
            except Exception:
                pname = "N/A"                 # If process info is unavailable
            conns.append({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'laddr': f"{c.laddr.ip}:{c.laddr.port}",   # Local IP and port
                'raddr': f"{c.raddr.ip}:{c.raddr.port}",   # Remote IP and port
                'status': c.status,                        # Connection status (e.g., ESTABLISHED)
                'pid': c.pid,                              # Process ID
                'process': pname                           # Process name
            })
    return conns

def detect_intrusion(conn, malicious_ips):
    """
    Multi-criteria intrusion detection for network connections.
    Returns (list_of_alerts, ip_to_add_to_blacklist).
    """
    alerts = []
    add_ip = False

    try:
        remote_ip, remote_port = conn['raddr'].split(':')
        port = int(remote_port)
    except Exception:
        remote_ip, port = "0.0.0.0", 0

    # 1. Alert if remote port is in the list of critical/dangerous ports
    if port in CRITICAL_PORTS:
        alerts.append(f"Connection to critical port {port} ({CRITICAL_PORTS[port]})")
        add_ip = True

    # 2. Alert if the remote IP is already blacklisted
    if remote_ip in malicious_ips:
        alerts.append("Known malicious IP")

    # 3. Alert if a system process uses a high port (unusual behavior)
    if conn['process'] in ['explorer.exe', 'svchost.exe'] and port > 1024:
        alerts.append("System process on non-privileged port")
        add_ip = True

    # 4. Alert if DNS traffic is seen from an unexpected process
    if port == 53 and conn['process'] not in ['dnsmasq', 'named']:
        alerts.append("Unusual DNS traffic")
        add_ip = True

    # 5. Alert if the process name is in a list of suspicious processes
    suspicious_processes = {'nc', 'telnet', 'meterpreter'}
    if conn['process'].lower() in suspicious_processes:
        alerts.append(f"Suspicious process: {conn['process']}")
        add_ip = True

    # 6. Alert if the port is very high (outside of common usage)
    if port > 50000:
        alerts.append("Unusually high port")
        add_ip = True

    # Add the IP to the blacklist if it triggered an alert and is not already blacklisted
    if add_ip and remote_ip not in malicious_ips and remote_ip != "0.0.0.0":
        return alerts, remote_ip
    return alerts, None

def block_internet():
    """
    Disables the main network interface to block Internet access.
    Adjust interface names for your system if needed.
    """
    system = platform.system()
    print("Blocking internet access due to intrusion detection!")
    if system == "Windows":
        # Replace 'Wi-Fi' with your actual interface name if needed
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        # Replace 'wlan0' with your actual Wi-Fi interface name
        os.system('nmcli radio wifi off')
        # For Ethernet: os.system('nmcli networking off')
    else:
        print("Blocking not implemented for this OS.")

def unblock_internet():
    """
    Re-enables the main network interface.
    """
    system = platform.system()
    print("Re-enabling internet access.")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=enable')
    elif system == "Linux":
        os.system('nmcli radio wifi on')
        # For Ethernet: os.system('nmcli networking on')
    else:
        print("Unblocking not implemented for this OS.")

def main():
    report = []
    malicious_ips = load_malicious_ips()
    internet_blocked = False

    while True:
        conns = get_connections()
        updated = False
        intrusion_detected = False

        for conn in conns:
            alerts, new_ip = detect_intrusion(conn, malicious_ips)
            if alerts:
                alert_msg = " | ".join(alerts)
                print(f"ALERT: {alert_msg} - Connection: {conn}")
                conn['ALERT'] = alert_msg
                intrusion_detected = True
                # Dynamically add new IPs to the blacklist if necessary
                if new_ip:
                    malicious_ips.add(new_ip)
                    updated = True
                    print(f"New IP added to blacklist: {new_ip}")
            else:
                conn['ALERT'] = ''
            report.append(conn)

        # Save the updated blacklist if it changed
        if updated:
            save_malicious_ips(malicious_ips)

        # Save the network activity report to CSV
        if report:
            df = pd.DataFrame(report)
            df.to_csv("network_report.csv", index=False)
        report.clear()

        # Block internet if intrusion detected and not already blocked
        if intrusion_detected and not internet_blocked:
            block_internet()
            internet_blocked = True

        
        # if internet_blocked:
        #     time.sleep(60)
        #     unblock_internet()
        #     internet_blocked = False

        time.sleep(60)  # Wait 60 seconds before the next check

if __name__ == "__main__":
    main()

