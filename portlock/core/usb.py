import wmi
import win32file
import win32api
import subprocess

def get_all_usb_serials():
    c = wmi.WMI()
    serial_map = {}

    for disk in c.Win32_DiskDrive():
        if "USB" in disk.InterfaceType:
            serial = disk.PNPDeviceID.split("\\")[-1]
            partitions = disk.associators("Win32_DiskDriveToDiskPartition")
            for partition in partitions:
                logical_disks = partition.associators("Win32_LogicalDiskToPartition")
                for ld in logical_disks:
                    serial_map[serial] = ld.DeviceID
    return serial_map  # {serial: "E:"}

def find_drive_letter_by_serial(serial):
    usb_map = get_all_usb_serials()
    for s, drive_letter in usb_map.items():
        if s == serial:
            return drive_letter
    return None

def eject_usb(serial):
    drive_letter = find_drive_letter_by_serial(serial)
    if drive_letter:
        try:
            handle = win32file.CreateFile(
                f"\\\\.\\{drive_letter}:",
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            win32file.DeviceIoControl(
                handle,
                IOCTL_STORAGE_MEDIA_REMOVAL,
                b'\x01',
                None
            )
            win32file.DeviceIoControl(
                handle,
                IOCTL_STORAGE_EJECT_MEDIA,
                None,
                0,
                None
            )
            win32api.CloseHandle(handle)
            print(f"[EJECTED] (win32) USB drive {drive_letter}:")
        except Exception as e:
            print(f"[!] Failed to eject USB via win32: {e}")
            # Fallback to PowerShell WMI eject
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-Command",
                        f"$drive = gwmi -Class Win32_Volume | Where-Object {{$_.DriveLetter -eq '{drive_letter}:'}}; if ($drive) {{$drive.Eject()}}"
                    ],
                    capture_output=True, text=True
                )
                print(f"[EJECTED] (powershell) USB drive {drive_letter}:")
            except Exception as e2:
                print(f"[!] Failed to eject USB via powershell: {e2}")
    else:
        print(f"[!] Could not find drive letter for serial {serial}")

# Example usage
if __name__ == "__main__":
    # Get all USBs
    devices = get_all_usb_serials()
    print("[*] Connected USB Devices:")
    for s, d in devices.items():
        print(f"  - Serial: {s}  →  Drive: {d}")

    # Pick the first device to eject for testing
    if devices:
        first_serial = list(devices.keys())[0]
        eject_usb(first_serial)
    else:
        print("[!] No USB devices found.")
