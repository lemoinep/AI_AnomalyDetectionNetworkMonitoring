# Author(s): Dr. Patrick Lemoine
# ADD Bluetooth scanning

import psutil
import pandas as pd
import time
from datetime import datetime
import json
import os
import platform
import bluetooth 

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


# List of authorized Bluetooth MAC addresses
AUTHORIZED_BLUETOOTH_MACS = {""}


def build_bluetooth_macs():
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
    

def save_bluetooth_macs(mac_set, filename="list_bluetooth_macs.json"):
    """
    Saves the set of authorized Bluetooth MAC addresses to a JSON file.
    :param mac_set: set of MAC addresses (strings)
    :param filename: filename to save to (default: 'authorized_bluetooth_macs.json')
    """
    with open(filename, "w") as f:
        json.dump(sorted(list(mac_set)), f, indent=2)
    print(f"Saved {len(mac_set)} authorized Bluetooth MAC addresses to {filename}")
 
 
def load_authorized_bluetooth_macs(filename="authorized_bluetooth_macs.json"):
    """
    Loads the set of authorized Bluetooth MAC addresses from a JSON file.
    :param filename: filename to load from (default: 'authorized_bluetooth_macs.json')
    :return: set of MAC addresses (strings)
    """
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()
 
 
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
    print("[Network] Blocking internet access due to intrusion detection!")
    if system == "Windows":
        # Replace 'Wi-Fi' with your actual interface name if needed
        os.system('netsh interface set interface "Wi-Fi" admin=disable')
    elif system == "Linux":
        # Replace 'wlan0' with your actual Wi-Fi interface name
        os.system('nmcli radio wifi off')
        # For Ethernet: os.system('nmcli networking off')
    else:
        print("[Network] Blocking not implemented for this OS.")

def unblock_internet():
    """
    Re-enables the main network interface.
    """
    system = platform.system()
    print("[Network] Re-enabling internet access.")
    if system == "Windows":
        os.system('netsh interface set interface "Wi-Fi" admin=enable')
    elif system == "Linux":
        os.system('nmcli radio wifi on')
        # For Ethernet: os.system('nmcli networking on')
    else:
        print("[Network] Unblocking not implemented for this OS.")

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

def detect_bluetooth_intrusion(devices):
    """
    Checks scanned Bluetooth devices against the authorized list.
    Returns a list of alerts for unauthorized devices.
    """
    alerts = []
    for addr, name in devices:
        if addr not in AUTHORIZED_BLUETOOTH_MACS:
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

def main():
    report = []
    malicious_ips = load_malicious_ips()
    internet_blocked = False
    bluetooth_blocked = False
    
    # List of authorized Bluetooth MAC addresses
    LIST_BLUETOOTH_MACS_ALPHA = build_bluetooth_macs()
    save_bluetooth_macs(LIST_BLUETOOTH_MACS)
    
    # AUTHORIZED_BLUETOOTH_MACS only on your laptop
    AUTHORIZED_BLUETOOTH_MACS = load_authorized_bluetooth_macs()

    while True:
        # --- Network surveillance ---
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

        # --- Bluetooth surveillance ---
        bt_devices = scan_bluetooth_devices()
        bt_alerts = detect_bluetooth_intrusion(bt_devices)
        if bt_alerts and not bluetooth_blocked:
            for alert in bt_alerts:
                print(f"ALERT: {alert}")
            block_bluetooth()
            bluetooth_blocked = True

        # Wait 60 seconds before next check
        time.sleep(60)

if __name__ == "__main__":
    main()
