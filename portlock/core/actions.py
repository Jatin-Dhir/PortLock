from .logger import log_event
from .whitelist import is_whitelisted, add_to_whitelist
from .password import verify_password
from .usb import eject_usb

def handle_device_inserted(serial):
    if not is_whitelisted(serial):
        eject_usb(serial)  # Eject immediately
        print("[!] Unknown USB device detected and ejected!")
        password = input("🔐 Enter admin password to allow this device: ")
        if verify_password(password):
            add_to_whitelist(serial)
            print("[+] Correct password. Please reinsert the USB device.")
        else:
            print("[-] Incorrect password. Access blocked. Device remains ejected.")
    else:
        print("[+] Whitelisted USB device detected. Access granted.")

def handle_device_removed(serial):
    print(f"[-] USB device removed: {serial}")
    log_event("removed", serial)  # Use correct arguments
