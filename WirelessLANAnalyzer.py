# Author(s): Dr. Patrick Lemoine

import sys
import platform
import time
import subprocess
import re

try:
    from mac_vendor_lookup import MacLookup
    vendor_lookup = MacLookup()
    vendor_db_ok = True
    # Please Uncomment this line on first run to download the database:
    # vendor_lookup.update_vendors()
except ImportError:
    vendor_lookup = None
    vendor_db_ok = False

def scan_wifi_linux(interface='wlan0'):
    try:
        from rssi import RSSI_Scan
    except ImportError:
        print("Install the rssi library via 'pip install rssi'")
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
        print("Error during Wifi scan:", e)
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
    import os
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"\nDetected wifi networks: {len(networks)} network(s)")
    print("="*50)
    if not networks:
        print("No networks detected. Retrying...")
    else:
        for idx, net in enumerate(networks):
            print(f"{idx+1}. SSID: {net['ssid']} | Signal: {net['signal']}")
    print("="*50)

def scan_connected_devices_windows():
    try:
        arp_output = subprocess.check_output('arp -a', shell=True, text=True)
    except Exception as e:
        print(f"Error running arp: {e}")
        return []
    devices = []
    for line in arp_output.splitlines():
        match = re.match(r"^(\S+)\s+([\w\-]+)\s+\S+", line.strip())
        if match:
            ip = match.group(1)
            mac = match.group(2)
            devices.append({'ip': ip, 'mac': mac})
    return devices

def scan_connected_devices_linux():
    try:
        ip_route = subprocess.check_output("hostname -I", shell=True, text=True).strip().split()[0]
        network_prefix = ".".join(ip_route.split('.')[:3]) + '.0/24'
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
            devices.append({'ip': ip, 'mac': mac})
    return devices

def is_phone(mac, vendor_lookup=None):
    if not vendor_lookup or not mac or mac == "??":
        return False
    try:
        vendor = vendor_lookup.lookup(mac)
        phone_keywords = ["apple", "samsung", "xiaomi", "oppo", "huawei", "oneplus", "sony", "google", "htc", "motorola", "nokia", "realme", "lenovo", "asus", "lg", "zte", "infinix", "tecno", "vivo", "meizu", "sharp"]
        if any(word in vendor.lower() for word in phone_keywords):
            return True
    except Exception:
        pass
    return False

def show_devices(devices):
    print("\nDevices connected to the local network:")
    print("="*50)
    if not devices:
        print("No devices detected.")
    else:
        for idx, dev in enumerate(devices):
            mac = dev['mac'] if dev['mac'] else "??"
            vendor_str = phone_str = debug_str = ""
            if vendor_db_ok and mac != "??":
                try:
                    vendor = vendor_lookup.lookup(mac)
                    vendor_str = f" | Vendor: {vendor}"
                    debug_str = f" (debug: {vendor})"
                    if is_phone(mac, vendor_lookup):
                        phone_str = " | Phone detected!"
                except Exception as e:
                    vendor_str = ""
                    debug_str = f" (vendor lookup failed: {e})"
            print(f"{idx+1}. IP: {dev['ip']} | MAC: {mac}{vendor_str}{phone_str}{debug_str}")
    print("="*50)

def main_monitoring(os_type=None, interface='wlan0', interval=5, scan_devices=False):
    try:
        import keyboard
    except ImportError:
        print("Install keyboard via 'pip install keyboard'")
        return

    if os_type is None:
        current_os = platform.system().lower()
    else:
        current_os = os_type.lower()

    print("WiFi Monitor (ESC to quit)...\n")
    last_networks = []

    try:
        while True:
            if current_os.startswith('win'):
                networks = scan_wifi_windows()
            elif current_os.startswith('linux'):
                networks = scan_wifi_linux(interface)
            else:
                print("This script only supports Windows and Linux.")
                return
            if networks:
                last_networks = networks
            show_networks(last_networks)

            if scan_devices:
                if current_os.startswith('win'):
                    devices = scan_connected_devices_windows()
                else:
                    devices = scan_connected_devices_linux()
                show_devices(devices)

            print(f"\nNext update in {interval}s... ESC to quit.")
            t0 = time.time()
            while time.time() - t0 < interval:
                if keyboard.is_pressed('esc'):
                    print("\nStopping monitoring.")
                    return
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nManual stop of monitoring.")

if __name__ == "__main__":
    # Windows: main_monitoring('windows', scan_devices=True)
    # Linux: main_monitoring('linux', 'wlan0', scan_devices=True)
    main_monitoring('windows', scan_devices=True)
