from .core.usb import get_connected_usb_serials
from .core.actions import handle_device_inserted, handle_device_removed
import time

def monitor_usb():
    print("[*] Monitoring USB ports... Press Ctrl+C to stop.")
    known_devices = set(get_connected_usb_serials())

    while True:
        try:
            current_devices = set(get_connected_usb_serials())
            inserted = current_devices - known_devices
            removed = known_devices - current_devices

            for serial in inserted:
                handle_device_inserted(serial)

            for serial in removed:
                handle_device_removed(serial)

            known_devices = current_devices
            time.sleep(1.5)
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped.")
            break
        except Exception as e:
            print(f"[!] Monitor error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    monitor_usb()

def handle_device_removed(serial):
    print(f"[-] USB device removed: {serial}")
