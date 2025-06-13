# Classic approach without AI

import psutil
import pandas as pd
import time
from datetime import datetime

def get_connections():
    """
    Retrieves a list of current active network connections.
    For each connection, gathers information such as timestamp, local and remote addresses,
    status, process ID, and process name.
    Only includes connections that have a remote address (i.e., established connections).
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

def detect_intrusion(conn):
    """
    Simple intrusion detection example :
    Triggers an alert if the remote port is unusual (greater than 50000).
    To do add more options
    """
    try:
        port = int(conn['raddr'].split(':')[1])  # Extract the remote port number
        if port > 50000:
            return True
    except:
        pass
    return False

def main():
    report = []
    while True:
        conns = get_connections()  # Get current network connections
        for conn in conns:
            if detect_intrusion(conn):
                print(f"ALERT: Suspicious connection detected: {conn}")
                conn['ALERT'] = 'YES'
            else:
                conn['ALERT'] = ''
            report.append(conn)
        # Save the report every 60 seconds to a CSV file
        if len(report) > 0:
            df = pd.DataFrame(report)
            df.to_csv("network_report.csv", index=False)
        report.clear()  # Clear the report for the next cycle
        time.sleep(60)  # Wait 60 seconds before the next check

if __name__ == "__main__":
    main()
