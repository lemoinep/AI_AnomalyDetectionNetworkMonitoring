import argparse
import platform
import subprocess
import sys
import time


# -------- Common helpers --------

def run_subprocess(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a subprocess and return the CompletedProcess."""
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


# -------- Linux implementation --------

def linux_get_connected_devices() -> list[tuple[str, str]]:
    """
    Returns a list of (MAC, Name) for connected Bluetooth devices on Linux. 🔗📶

    Uses:
      bluetoothctl devices Connected           (BlueZ >= 5)
    """
    # Try bluetoothctl first
    try:
        result = run_subprocess(["bluetoothctl", "devices", "Connected"])
    except FileNotFoundError:
        print("bluetoothctl is not available. Please install BlueZ (e.g. apt install bluez). 🛠️")
        return []

    if result.returncode != 0:
        print(f"[ERROR] bluetoothctl devices Connected failed: {result.stderr.strip()} 😞")
        return []

    devices = []
    for line in result.stdout.strip().splitlines():
        # Example: "Device AA:BB:CC:DD:EE:FF MyHeadphones"
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "Device":
            mac = parts[1]
            name = " ".join(parts[2:])
            devices.append((mac, name))

    return devices


def linux_print_status():
    """Print Linux Bluetooth connection status. 🐧"""
    devices = linux_get_connected_devices()

    if not devices:
        print("No Bluetooth devices are currently connected on Linux. 🚫📶")
        return

    print("Currently connected Bluetooth devices on Linux: 🔗📶\n")
    for mac, name in devices:
        print(f"  • {name} ({mac}) is CONNECTED ✅")


# -------- Windows implementation --------

def run_powershell_command(cmd: str) -> str:
    """
    Run a PowerShell command and return its stdout as text. 📜
    """
    try:
        result = run_subprocess(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd])
    except FileNotFoundError:
        print("PowerShell is not available. Please run this script on Windows with PowerShell installed. 🛠️")
        sys.exit(1)

    if result.returncode != 0 and not result.stdout.strip():
        print(f"[ERROR] PowerShell command failed: {result.stderr.strip()} 😞")
        sys.exit(1)

    return result.stdout.strip()


def windows_get_connected_bluetooth_devices() -> list[tuple[str, str]]:
    """
    Returns a list of (Name, DeviceID) for Bluetooth devices currently connected
    on Windows. 🔗📶

    Uses Win32_PnPEntity with Service = 'BTH' and Connected = True. [web:35][web:47][web:54]
    """
    ps_cmd = (
        'Get-WmiObject -Class Win32_PnPEntity '
        '| Where-Object { $_.Service -eq "BTH" -and $_.Connected } '
        '| Select-Object Name, DeviceID '
        '| ForEach-Object { $_.Name + "|" + $_.DeviceID }'
    )
    output = run_powershell_command(ps_cmd)

    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 1)
        if len(parts) == 2:
            name, device_id = parts
            devices.append((name, device_id))

    return devices


def windows_get_paired_bluetooth_devices() -> list[tuple[str, str]]:
    """
    Returns a list of (Name, Address) for Bluetooth devices that are paired
    (known) in Windows, even if not connected. 🤝

    Reads registry: HKLM:\\SYSTEM\\ControlSet001\\Services\\BTHPORT\\Parameters\\Devices [web:51]
    """
    ps_cmd = r'''
$devices = Get-ChildItem -Path HKLM:\SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Devices
foreach($device in $devices) {
    $address = $device.PSChildName.ToUpper()
    $name = $device.GetValue("Name")
    if ($name -ne $null) {
        $chars = @()
        foreach ($b in $name) { if ($b -ne 0) { $chars += [char]$b } }
        $printableName = -join $chars
        "$printableName|$address"
    }
}
'''
    output = run_powershell_command(ps_cmd)

    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 1)
        if len(parts) == 2:
            name, address = parts
            devices.append((name, address))

    return devices


def windows_print_status(show_paired: bool = False):
    """Print Windows Bluetooth connection status. 💻"""
    connected = windows_get_connected_bluetooth_devices()

    if connected:
        print("Currently connected Bluetooth devices on Windows: 🔗📶\n")
        for name, device_id in connected:
            print(f"  • {name} ({device_id}) is CONNECTED ✅")
    else:
        print("No Bluetooth devices are currently connected on Windows. 🚫📶")

    if show_paired:
        print("\nPaired Bluetooth devices (registry): 🤝")
        paired = windows_get_paired_bluetooth_devices()
        if paired:
            for name, address in paired:
                print(f"  • {name} (Address: {address})")
        else:
            print("  (No paired Bluetooth devices found in registry.)")


# -------- Main dispatch --------

def main():
    parser = argparse.ArgumentParser(
        description="Monitor Bluetooth connections on Linux or Windows. 🔍📶"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch Bluetooth connections in a loop (every 2 seconds). ⏱️",
    )
    parser.add_argument(
        "--show-paired",
        action="store_true",
        help="Also show paired Bluetooth devices (Windows only, registry). 🤝",
    )
    
    parser.add_argument(
        "--Path",
        type=str, default='.',
        help="Path",
    )

    args = parser.parse_args()

    system = platform.system()  # 'Linux', 'Windows', 'Darwin', etc. [web:61][web:63]

    if args.watch:
        print(f"Watching Bluetooth connections on {system} (refresh every 2 seconds)... 🔍📶\n")
        try:
            while True:
                print("-" * 60)
                if system == "Linux":
                    linux_print_status()
                elif system == "Windows":
                    windows_print_status(show_paired=args.show_paired)
                else:
                    print(f"Unsupported OS: {system}. Only Linux and Windows are handled currently. ⚠️")
                print("-" * 60 + "\n")
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nStopped watching Bluetooth connections. 🛑")
    else:
        print(f"Scanning Bluetooth connections on {system}... 🔍📶\n")
        if system == "Linux":
            linux_print_status()
        elif system == "Windows":
            windows_print_status(show_paired=args.show_paired)
        else:
            print(f"Unsupported OS: {system}. Only Linux and Windows are handled currently. ⚠️")


if __name__ == "__main__":
    main()  # 🏁