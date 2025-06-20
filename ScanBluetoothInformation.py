# Author(s): Dr. Patrick Lemoine

# GOAL :
# This program scans for nearby Bluetooth devices to help monitor and 
# detect unauthorized access.
# It allows users to select trusted devices and saves their MAC addresses 
# for future reference.
# The tool supports both Linux and Windows platforms, with enhanced features 
# for Linux such as RSSI-based distance estimation.
# Intrusion detection alerts are generated when new or 
# untrusted devices are found within range.
# Logging and user input validation are included 
# for improved robustness and usability    

import os
import platform
import json
import re
import subprocess
import time
import logging
import random
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt

try:
    import bluetooth
except ImportError:
    bluetooth = None

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

TO_BE_CHECKED_BLUETOOTH_MACS_FILE = "ToBeChecked_bluetooth_macs.json"

def estimate_distance_from_rssi(rssi, tx_power=-59):
    """
    Estimate the distance in meters from the RSSI value.
    tx_power: Transmission power at 1 meter (usually -59 dBm for Bluetooth).
    Returns a float representing the estimated distance.
    """
    if rssi == 0:
        return -1.0  # Cannot estimate distance
    ratio = rssi * 1.0 / tx_power
    if ratio < 1.0:
        return pow(ratio, 10)
    else:
        return 0.89976 * pow(ratio, 7.7095) + 0.111

def scan_bluetooth_linux(scan_duration=8):
    """
    Scan for Bluetooth devices on Linux using bluetoothctl.
    Returns a list of tuples: (mac, name, rssi, distance)
    """
    logger.info("Bluetooth scanning in progress (Linux)...")
    devices = []
    try:
        scan_process = subprocess.Popen(['bluetoothctl', 'scan', 'on'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(scan_duration)
        scan_process.terminate()
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
                    distance = estimate_distance_from_rssi(rssi)
                    devices.append((mac, name, rssi, distance))
                else:
                    devices.append((mac, name, None, None))
    except Exception as e:
        logger.error(f"Error during Bluetooth scan: {e}")
    return devices

def scan_bluetooth_other():
    """
    Scan for Bluetooth devices on Windows/macOS using PyBluez.
    Only device name and MAC address are available; RSSI and distance are not.
    Returns a list of tuples: (mac, name, None, None)
    """
    os_name = platform.system()
    if os_name == "Darwin":
        logger.warning("Bluetooth scanning not fully supported on macOS with PyBluez.")
        return []
    if bluetooth is None:
        logger.error("PyBluez module is not installed. Cannot scan for Bluetooth devices.")
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
    Scan for nearby Bluetooth devices and prompt the user to select trusted devices.
    Returns a set of trusted MAC addresses.
    """
    os_name = platform.system()
    scan_duration = int(input("Enter scan duration (seconds, default 8): ") or 8)
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
            indices = [int(i.strip())-1 for i in user_input.split(",")]
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
    Save the set of trusted MAC addresses to a JSON file.
    """
    try:
        with open(filename, "w") as f:
            json.dump(sorted(list(mac_set)), f, indent=2)
        logger.info(f"Saved {len(mac_set)} trusted Bluetooth MAC addresses to {filename}")
    except Exception as e:
        logger.error(f"Error saving file: {e}")

def load_to_be_checked_bluetooth_macs(filename=TO_BE_CHECKED_BLUETOOTH_MACS_FILE):
    """
    Load the set of trusted MAC addresses from a JSON file.
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
    Compare detected devices with the trusted list.
    Returns a list of alert messages for untrusted devices.
    """
    alerts = []
    for addr, name, rssi, distance in devices:
        if addr not in trusted_macs:
            if rssi is not None:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr}) | RSSI: {rssi} dBm | Estimated distance: {distance:.2f} m")
            else:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

def plot_bluetooth_devices_3d(devices):
    """
    Display detected Bluetooth devices in a 3D space.
    If the distance is known, it is used as the radius.
    Angles are assigned randomly due to lack of directionality.
    """
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    for idx, (mac, name, rssi, distance) in enumerate(devices):
        if distance is not None and distance > 0:
            # Random placement on a sphere of radius = distance
            theta = random.uniform(0, 2 * np.pi)  # azimuth
            phi = random.uniform(0, np.pi)        # elevation
            x = distance * np.sin(phi) * np.cos(theta)
            y = distance * np.sin(phi) * np.sin(theta)
            z = distance * np.cos(phi)
        else:
            # If no distance, place on a circle of arbitrary radius (e.g., 5)
            angle = 2 * np.pi * idx / max(1, len(devices))
            x, y, z = 5 * np.cos(angle), 5 * np.sin(angle), 0

        ax.scatter(x, y, z, label=f"{name} ({mac})")
        ax.text(x, y, z, name, fontsize=8)

    ax.set_xlabel('X (m)')
    ax.set_ylabel('Y (m)')
    ax.set_zlabel('Z (m)')
    ax.set_title('Estimated positions of Bluetooth sources')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    print("=== Build list of trusted Bluetooth devices ===")
    trusted_macs = build_to_be_checked_bluetooth_macs()
    save_to_be_checked_bluetooth_macs(trusted_macs)

    print("\n=== Bluetooth scan and intrusion detection ===")
    os_name = platform.system()
    scan_duration = int(input("Enter scan duration (seconds, default 8): ") or 8)
    if os_name == "Linux":
        devices = scan_bluetooth_linux(scan_duration)
    else:
        devices = scan_bluetooth_other()

    trusted_macs = load_to_be_checked_bluetooth_macs()
    alerts = detect_bluetooth_intrusion(devices, trusted_macs)
    if alerts:
        print("\nALERTS:")
        for alert in alerts:
            print(alert)
    else:
        print("No intrusion detected.")

    # Optional: Offer 3D visualization if any distances are available
    if any(d[3] is not None for d in devices):
        show_3d = input("\nWould you like to display a 3D representation of estimated positions? (y/n): ")
        if show_3d.lower().startswith('y'):
            plot_bluetooth_devices_3d(devices)

