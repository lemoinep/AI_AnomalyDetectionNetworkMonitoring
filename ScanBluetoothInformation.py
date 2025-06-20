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

try:
    import bluetooth
except ImportError:
    bluetooth = None

# Loggins Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ToBeChecked_BLUETOOTH_MACS_FILE = "ToBeChecked_bluetooth_macs.json"

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

def build_ToBeChecked_bluetooth_macs():
    """
    Scan for nearby Bluetooth devices and prompt the user to select ToBeChecked devices.
    Returns a set of ToBeChecked MAC addresses.
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
    ToBeChecked = set()
    while True:
        user_input = input("\nEnter the numbers (comma-separated) of devices you want to authorize, or press Enter to skip: ")
        if not user_input.strip():
            break
        try:
            indices = [int(i.strip())-1 for i in user_input.split(",")]
            for i in indices:
                if 0 <= i < len(devices):
                    ToBeChecked.add(devices[i][0])
            break
        except Exception as e:
            print(f"Invalid input: {e}. Please try again.")
    print(f"\nToBeChecked_BLUETOOTH_MACS = {ToBeChecked}")
    return ToBeChecked

def save_ToBeChecked_bluetooth_macs(mac_set, filename=ToBeChecked_BLUETOOTH_MACS_FILE):
    """
    Save the set of ToBeChecked MAC addresses to a JSON file.
    """
    try:
        with open(filename, "w") as f:
            json.dump(sorted(list(mac_set)), f, indent=2)
        logger.info(f"Saved {len(mac_set)} ToBeChecked Bluetooth MAC addresses to {filename}")
    except Exception as e:
        logger.error(f"Error saving file: {e}")

def load_ToBeChecked_bluetooth_macs(filename=ToBeChecked_BLUETOOTH_MACS_FILE):
    """
    Load the set of ToBeChecked MAC addresses from a JSON file.
    Returns a set of MAC addresses.
    """
    try:
        with open(filename, "r") as f:
            return set(json.load(f))
    except Exception as e:
        logger.error(f"Error loading file: {e}")
        return set()

def detect_bluetooth_intrusion(devices, ToBeChecked_macs):
    """
    Compare detected devices with the ToBeChecked list.
    Returns a list of alert messages for unToBeChecked devices.
    """
    alerts = []
    for addr, name, rssi, distance in devices:
        if addr not in ToBeChecked_macs:
            if rssi is not None:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr}) | RSSI: {rssi} dBm | Estimated distance: {distance:.2f} m")
            else:
                alerts.append(f"Bluetooth intrusion detected: {name} ({addr})")
    return alerts

if __name__ == "__main__":
    print("=== Build list of ToBeChecked Bluetooth devices ===")
    ToBeChecked_macs = build_ToBeChecked_bluetooth_macs()
    save_ToBeChecked_bluetooth_macs(ToBeChecked_macs)

    print("\n=== Bluetooth scan and intrusion detection ===")
    os_name = platform.system()
    scan_duration = int(input("Enter scan duration (seconds, default 8): ") or 8)
    if os_name == "Linux":
        devices = scan_bluetooth_linux(scan_duration)
    else:
        devices = scan_bluetooth_other()

    ToBeChecked_macs = load_ToBeChecked_bluetooth_macs()
    alerts = detect_bluetooth_intrusion(devices, ToBeChecked_macs)
    if alerts:
        print("\nALERTS:")
        for alert in alerts:
            print(alert)
    else:
        print("No intrusion detected.")
