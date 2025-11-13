# Author(s): Dr. Patrick Lemoine

import sys
import platform
import time
import subprocess
import re
import os
import csv
from datetime import datetime

# MAC Vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    vendor_lookup = MacLookup()
    vendor_db_ok = True
    try:
        vendor_lookup.update_vendors()
    except Exception as e:
        print(f"update_vendors error: {e}")
except ImportError:
    vendor_lookup = None
    vendor_db_ok = False

def get_subnet_base():
    try:
        current_os = platform.system().lower()
        if current_os.startswith('win'):
            ip_output = subprocess.check_output("ipconfig", shell=True, text=True, encoding='utf-8')
            ip_match = re.search(r"IPv4.*?:\s*([0-9\.]+)", ip_output)
            if ip_match:
                ip_addr = ip_match.group(1)
            else:
                ip_addr = "192.168.1.1"
        else:
            ip_addr = subprocess.check_output("hostname -I", shell=True, text=True).strip().split()[0]
        subnet_parts = ip_addr.split('.')
        if len(subnet_parts) >= 3:
            return f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}."
        else:
            return "192.168.1."
    except Exception as e:
        print(f"Subnet detection error: {e}")
        return "192.168.1."

def scan_wifi_linux(interface='wlan0'):
    try:
        from rssi import RSSI_Scan
    except ImportError:
        print("Please install the rssi library via 'pip install rssi'")
        return []
    for attempt in range(3):
        try:
            scanner = RSSI_Scan(interface)
            aps = scanner.getAPinfo(sudo=True)
            networks = []
            if aps:
                for ap in aps:
                    ssid = ap.get('ssid', '(unknown)')
                    signal = ap.get('signal', 'N/A')
                    if ssid and ssid != '(unknown)':
                        networks.append({'ssid': ssid, 'signal': signal})
            if networks:
                return networks
            time.sleep(1)
        except Exception as e:
            print(f"Linux scan error attempt {attempt+1}: {e}")
            time.sleep(1)
    return []

def scan_wifi_windows():
    command = "netsh wlan show networks mode=Bssid"
    try:
        output = subprocess.check_output(command, shell=True, text=True, encoding='utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        print("WiFi scan error:", e)
        return []
    networks = []
    current_ssid = None
    for line in output.split('\n'):
        line = line.strip()
        ssid_match = re.match(r"^SSID \d+ : (.+)", line)
        if ssid_match:
            current_ssid = ssid_match.group(1)
        bssid_match = re.match(r"^BSSID \d+ : ([\w:]+)", line)
        if bssid_match:
            current_bssid = bssid_match.group(1)
            signal = None
        if "Signal" in line and current_ssid:
            try:
                signal_val = int(re.findall(r"(\d+)%", line)[0])
            except Exception:
                signal_val = None
            networks.append({'ssid': current_ssid, 'signal': f"{signal_val}%" if signal_val is not None else "??"})
    return networks

def show_networks(networks):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Detected WiFi networks ({len(networks)})")
    print("="*50)
    if not networks:
        print("No networks detected. Retrying...")
    else:
        for idx, net in enumerate(networks):
            print(f"{idx+1}. SSID : {net['ssid']} | Signal : {net['signal']}")
    print("="*50)

def ping_sweep_windows(subnet_base, start=1, end=254):
    processes = []
    for i in range(start, end+1):
        ip = f"{subnet_base}{i}"
        p = subprocess.Popen(f"ping -n 1 -w 100 {ip}", shell=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(p)
    for p in processes:
        p.wait()

def scan_connected_devices_windows(subnet_base):
    ping_sweep_windows(subnet_base)
    time.sleep(0.5)
    try:
        arp_output = subprocess.check_output('arp -a', shell=True, text=True)
    except Exception as e:
        print(f"Error running arp: {e}")
        return []
    devices = []
    for line in arp_output.splitlines():
        line = line.strip()
        if line.startswith("Interface:") or line.startswith("Internet") or not line:
            continue
        match = re.match(
            r"^(?P<ip>(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})\s+"
            r"(?P<mac>([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})\s+\S+", 
            line
        )
        if match:
            ip = match.group("ip")
            mac = match.group("mac").replace('-', ':').lower()
            if mac == 'ff:ff:ff:ff:ff:ff':
                continue
            devices.append({'ip': ip, 'mac': mac})
    return devices

def scan_connected_devices_linux():
    if os.system("which nmap > /dev/null 2>&1") != 0:
        print("Please install 'nmap' on your system: sudo apt install nmap")
        return []
    try:
        ip_route = subprocess.check_output("hostname -I", shell=True, text=True).strip().split()[0]
        network_prefix = ".".join(ip_route.split('.')[:3]) + '.0/24'
        print(f"Nmap scan on: {network_prefix}")
        nmap_output = subprocess.check_output(f"nmap -sn {network_prefix}", shell=True, text=True)
    except Exception as e:
        print(f"Error running nmap: {e}")
        return []
    devices = []
    lines = nmap_output.splitlines()
    for idx, line in enumerate(lines):
        if "Nmap scan report for" in line:
            ip = line.split()[-1]
            mac = None
            if idx + 1 < len(lines) and "MAC Address" in lines[idx+1]:
                try:
                    mac = lines[idx+1].split('MAC Address:')[1].split(' ')[1]
                except Exception:
                    mac = None
            if ((ip.startswith('192.168.') or ip.startswith('10.') or
                (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31))):
                if mac and mac.lower() != 'ff:ff:ff:ff:ff:ff':
                    devices.append({'ip': ip, 'mac': mac.lower()})
    return devices

def is_phone(mac, vendor_lookup=None):
    if not vendor_lookup or not mac or mac == "??":
        return False
    try:
        vendor = vendor_lookup.lookup(mac)
        phone_keywords = [
            "apple", "samsung", "xiaomi", "oppo", "huawei", "oneplus", "sony",
            "google", "htc", "motorola", "nokia", "realme", "lenovo",
            "asus", "lg", "zte", "infinix", "tecno", "vivo", "meizu", "sharp"
        ]
        if any(word in vendor.lower() for word in phone_keywords):
            return True
    except Exception:
        pass
    return False

def is_laptop(mac, vendor_lookup=None):
    if not vendor_lookup or not mac or mac == "??":
        return False
    try:
        vendor = vendor_lookup.lookup(mac)
        laptop_keywords = [
            "dell", "lenovo", "hp", "asus", "acer", "apple", "msi", "samsung",
            "toshiba", "huawei", "lg", "medion", "fujitsu", "gigabyte",
            "sony", "panasonic"
        ]
        if any(word in vendor.lower() for word in laptop_keywords):
            return True
    except Exception:
        pass
    return False

def show_mobile_and_laptop(devices):
    print("\nLaptops and phones detected on the local network:")
    print("No | IP              | MAC                | Manufacturer        | Type")
    print("-"*70)
    count = 0
    for idx, dev in enumerate(devices):
        mac = dev['mac'] if dev['mac'] else "??"
        vendor_str = "Unknown"
        type_str = "Other"
        if vendor_db_ok and mac != "??":
            try:
                vendor = vendor_lookup.lookup(mac)
                vendor_str = f"{vendor[:20]:20}"
                if is_phone(mac, vendor_lookup):
                    type_str = "Phone"
                elif is_laptop(mac, vendor_lookup):
                    type_str = "Laptop"
                else:
                    continue  # Ignore other devices
            except Exception:
                vendor_str = "Unknown"
                type_str = "Unknown"
        else:
            continue
        print(f"{count+1:<2} | {dev['ip']:<15} | {mac:<18} | {vendor_str:<20} | {type_str}")
        count += 1
    if count == 0:
        print("No laptops or phones detected.")
    print("-"*70)

def export_csv(devices, filename="network_devices.csv"):
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['ip', 'mac', 'manufacturer', 'type'])
        for dev in devices:
            mac = dev['mac'] if dev['mac'] else "??"
            try:
                manufacturer = vendor_lookup.lookup(mac) if vendor_db_ok and mac != "??" else "??"
            except Exception:
                manufacturer = "Unknown"
            type_str = "Phone" if is_phone(mac, vendor_lookup) else ("Laptop" if is_laptop(mac, vendor_lookup) else "Other")
            writer.writerow([dev['ip'], mac, manufacturer, type_str])
    print(f"List exported to {filename}")

def main_monitoring(
    os_type=None, 
    interface='wlan0', 
    interval=5, 
    scan_devices=False, 
    export=False, 
    subnet_base=None
):
    try:
        import keyboard
    except ImportError:
        print("Please install keyboard via 'pip install keyboard'")
        return

    if subnet_base is None:
        subnet_base = get_subnet_base()

    if os_type is None:
        current_os = platform.system().lower()
    else:
        current_os = os_type.lower()

    print("\nDisplay legend: No = number in list, Only laptops/phones shown below")
    print("Warning: Devices with randomized MAC address are NOT detectable!")
    print("To detect a phone or laptop, disable the 'Random MAC address' mode in WiFi settings.")
    print(f"Current subnet base for scanning: {subnet_base}X")
    print("Press ESC to quit at any time.\n")
    last_networks = []
    devices = []

    try:
        while True:
            if current_os.startswith('win'):
                networks = scan_wifi_windows()
            elif current_os.startswith('linux'):
                networks = scan_wifi_linux(interface)
            else:
                print("This script supports only Windows and Linux.")
                return
            if networks:
                last_networks = networks
            show_networks(last_networks)

            if scan_devices:
                if current_os.startswith('win'):
                    devices = scan_connected_devices_windows(subnet_base=subnet_base)
                else:
                    devices = scan_connected_devices_linux()
                show_mobile_and_laptop(devices)
                if export:
                    export_csv(devices)

            print(f"\nNext refresh in {interval}s... ESC to quit.\n")
            t0 = time.time()
            while time.time() - t0 < interval:
                if keyboard.is_pressed('esc'):
                    print("\nStopping monitoring.")
                    return
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nManual stop of monitoring.")

if __name__ == "__main__":
    # subnet_base=None triggers dynamic detection (recommended)
    main_monitoring('windows', scan_devices=True, export=True, subnet_base=None)
    # To force a specific range, provide subnet_base, e.g. "10.0.0."
