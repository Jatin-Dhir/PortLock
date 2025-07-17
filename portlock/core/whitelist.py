import json
import os

WHITELIST_PATH = "data/whitelist.json"

def load_whitelist():
    if not os.path.exists(WHITELIST_PATH):
        return []
    with open(WHITELIST_PATH, "r") as f:
        return json.load(f)

def save_whitelist(whitelist):
    with open(WHITELIST_PATH, "w") as f:
        json.dump(whitelist, f, indent=4)

def is_whitelisted(serial):
    return serial in load_whitelist()

def add_to_whitelist(serial):
    whitelist = load_whitelist()
    if serial not in whitelist:
        whitelist.append(serial)
        save_whitelist(whitelist)
