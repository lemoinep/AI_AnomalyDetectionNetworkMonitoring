# Author(s): Dr. Patrick Lemoine

# Objective:
# Bluetooth-based tool to detect, track, and estimate the 3D positions of nearby devices, such as wireless earphones.  
# Uses Kalman-filtered RSSI measurements and trilateration for improved accuracy.  
# Supports trusted device lists, intrusion alerts, and optional 3D visualization.


import os
import platform
import json
import re
import subprocess
import time
import logging
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
from scipy.optimize import least_squares

try:
    import bluetooth
except ImportError:
    bluetooth = None

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

TO_BE_CHECKED_BLUETOOTH_MACS_FILE = "ToBeChecked_bluetooth_macs.json"

# --- Simple Kalman Filter class for smoothing RSSI values ---

class KalmanFilter:
    def __init__(self, process_variance=1e-3, measurement_variance=1e-2):
        self.process_variance = process_variance    # Variance of the process
        self.measurement_variance = measurement_variance  # Variance of the measurement noise
        self.posteri_estimate = None
        self.posteri_error_estimate = 1.0

    def update(self, measurement):
        if self.posteri_estimate is None:
            self.posteri_estimate = measurement
            return self.posteri_estimate
        priori_estimate = self.posteri_estimate
        priori_error_estimate = self.posteri_error_estimate + self.process_variance

        kalman_gain = priori_error_estimate / (priori_error_estimate + self.measurement_variance)
        self.posteri_estimate = priori_estimate + kalman_gain * (measurement - priori_estimate)
        self.posteri_error_estimate = (1 - kalman_gain) * priori_error_estimate

        return self.posteri_estimate

# Dictionary to hold Kalman filters per MAC address
rssi_filters = {}

def estimate_distance_from_rssi(rssi, tx_power=-59):
    """
    Basic estimation of distance from RSSI
    """
    if rssi == 0:
        return -1.0  # Cannot estimate distance
    ratio = rssi * 1.0 / tx_power
    if ratio < 1.0:
        return pow(ratio, 10)
    else:
        return 0.89976 * pow(ratio, 7.7095) + 0.111

def estimate_distance_from_rssi_kalman(mac, rssi, tx_power=-59):
    """
    Estimate distance by first filtering the RSSI with a Kalman filter specific to this MAC.
    """
    if mac not in rssi_filters:
        rssi_filters[mac] = KalmanFilter()
    filtered_rssi = rssi_filters[mac].update(rssi)
    return estimate_distance_from_rssi(filtered_rssi, tx_power)

def scan_bluetooth_linux(scan_duration=8):
    """
    Perform Bluetooth scan on Linux using bluetoothctl.
    Returns list of tuples: (mac, name, rssi, estimated_distance)
    """
    logger.info("Bluetooth scanning in progress (Linux)...")
    devices = []
    try:
        subprocess.Popen(['bluetoothctl', 'scan', 'on'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(scan_duration)
        subprocess.run(['bluetoothctl', 'scan', 'off'])
        result = subprocess.run(['bluetoothctl', 'devices'], stdout=subprocess.PIPE, text=True)
        for line in result.stdout.strip().split('\n'):
            match = re.match(r'Device ([0-9A-F:]+) (.+)', line)
            if match:
                mac = match.group(1)
                name = match.group(2)
                info = subprocess.run(['bluetoothctl', 'info', mac], stdout=subprocess.PIPE, text=True)
                rssi_match = re.search(r'RSSI: (-?\d+)', info.stdout)
                if rssi_match:
                    rssi = int(rssi_match.group(1))
                    distance = estimate_distance_from_rssi_kalman(mac, rssi)
                    devices.append((mac, name, rssi, distance))
                else:
                    devices.append((mac, name, None, None))
    except Exception as e:
        logger.error(f"Error during Bluetooth scan: {e}")
    return devices

def scan_bluetooth_other():
    """
    Bluetooth scan for Windows/macOS using PyBluez.
    Returns list of tuples: (mac, name, None, None) (no RSSI or distance)
    """
    os_name = platform.system()
    if os_name == "Darwin":
        logger.warning("Bluetooth scanning is not fully supported on macOS with PyBluez.")
        return []
    if bluetooth is None:
        logger.error("PyBluez module not installed, cannot scan Bluetooth devices.")
        return []
    logger.info("Bluetooth scanning in progress (Windows/macOS)...")
    try:
        devices = bluetooth.discover_devices(duration=8, lookup_names=True)
        return [(addr, name, None, None) for addr, name in devices]
    except Exception as e:
        logger.error(f"Bluetooth scan error: {e}")
        return []

def build_to_be_checked_bluetooth_macs():
    """
    Scan nearby Bluetooth devices and prompt user to select trusted devices.
    Returns a set of trusted MAC addresses.
    """
    os_name = platform.system()
    scan_duration = int(input("Enter scan duration in seconds (default 8): ") or 8)
    if os_name == "Linux":
        devices = scan_bluetooth_linux(scan_duration)
    else:
        devices = scan_bluetooth_other()
    if not devices:
        print("No Bluetooth devices found.")
        return set()
    print("\nFound Bluetooth devices:")
    for idx, (addr, name, rssi, distance) in enumerate(devices):
        if rssi is not None:
            print(f"{idx+1}. {name} ({addr}) | RSSI: {rssi} dBm | Estimated distance: {distance:.2f} m")
        else:
            print(f"{idx+1}. {name} ({addr})")
    trusted = set()
    while True:
        user_input = input("\nEnter the numbers (comma-separated) of devices you want to authorize, or press Enter to skip: ")
        if not user_input.strip():
            break
        try:
            indices = [int(i.strip()) - 1 for i in user_input.split(",")]
            for i in indices:
                if 0 <= i < len(devices):
                    trusted.add(devices[i][0])
            break
        except Exception as e:
            print(f"Invalid input: {e}. Please try again.")
    print(f"\nTrusted Bluetooth MACs = {trusted}")
    return trusted

def save_to_be_checked_bluetooth_macs(mac_set, filename=TO_BE_CHECKED_BLUETOOTH_MACS_FILE):
    """
    Save the trusted MAC addresses to a JSON file.
    """
    try:
        with open(filename, "w") as f:
            json.dump(sorted(list(mac_set)), f, indent=2)
        logger.info(f"Saved {len(mac_set)} trusted Bluetooth MAC addresses to {filename}")
    except Exception as e:
        logger.error(f"Error saving file: {e}")

def load_to_be_checked_bluetooth_macs(filename=TO_BE_CHECKED_BLUETOOTH_MACS_FILE):
    """
    Load trusted MAC addresses from a JSON file.
    Returns a set of MAC addresses.
    """
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception as e:
        logger.error(f"Error loading file: {e}")
        return set()

def detect_bluetooth_intrusion(devices, trusted_macs):
    """
    Compare detected devices with trusted list and return alerts for untrusted devices.
    """
    alerts = []
    for addr, name, rssi, distance in devices:
        if addr not in trusted_macs:
            if rssi is not None:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr}) | RSSI: {rssi} dBm | Estimated distance: {distance:.2f} m")
            else:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def collect_scan_data():
    """
    Collect scan data from multiple positions.
    Returns a dict mapping MAC addresses to lists of (x, y, distance) tuples.
    """
    scan_data = {}
    num_scans = int(input("Enter the number of scans from different positions: "))
    for i in range(num_scans):
        input(f"Move your laptop to position {i+1} and press Enter to continue...")
        os_name = platform.system()
        scan_duration = int(input("Enter scan duration in seconds (default 8): ") or 8)
        if os_name == "Linux":
            devices = scan_bluetooth_linux(scan_duration)
        else:
            devices = scan_bluetooth_other()
        x = float(input(f"Enter the x-coordinate of position {i+1}: "))
        y = float(input(f"Enter the y-coordinate of position {i+1}: "))
        for mac, name, rssi, distance in devices:
            if distance is not None and distance > 0:
                if mac not in scan_data:
                    scan_data[mac] = []
                scan_data[mac].append((x, y, distance))
    return scan_data

def equations(vars, x, y, distance):
    xi, yi, zi = vars
    return (xi - x)**2 + (yi - y)**2 + zi**2 - distance**2

def trilateration(points):
    """
    Calculate 3D position using trilateration.
    Input: list of (x, y, distance) tuples.
    Returns (x, y, z).
    """
    x0 = [0, 0, 0]
    result = least_squares(lambda vars: [equations(vars, x, y, d) for x, y, d in points], x0)
    return result.x

def plot_bluetooth_devices_3d(scan_data):
    """
    Display detected Bluetooth devices in 3D space.
    """
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    for mac, points in scan_data.items():
        if len(points) >= 3:
            x, y, z = trilateration(points)
            ax.scatter(x, y, z, label=f"Device {mac}")
            ax.text(x, y, z, f"Device {mac}", fontsize=8)

    ax.set_xlabel('X (m)')
    ax.set_ylabel('Y (m)')
    ax.set_zlabel('Z (m)')
    ax.set_title('Estimated positions of Bluetooth devices')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    print("=== Build list of trusted Bluetooth devices ===")
    trusted_macs = build_to_be_checked_bluetooth_macs()
    save_to_be_checked_bluetooth_macs(trusted_macs)

    print("\n=== Bluetooth scan and intrusion detection ===")
    scan_data = collect_scan_data()

    print("\n=== Estimated 3D positions of Bluetooth devices ===")
    for mac, points in scan_data.items():
        if len(points) >= 3:
            x, y, z = trilateration(points)
            print(f"Device {mac}: x = {x:.2f} m, y = {y:.2f} m, z = {z:.2f} m")

    # Optional: offer 3D visualization of results
    if scan_data:
        show_3d = input("\nWould you like to display a 3D visualization of estimated positions? (y/n): ")
        if show_3d.lower().startswith('y'):
            plot_bluetooth_devices_3d(scan_data)
