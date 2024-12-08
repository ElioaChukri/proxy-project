from pathlib import Path
from typing import List
from .allowlist import access_control

WHITELIST_PATH = Path("../whitelist.txt")
BLACKLIST_PATH = Path("../blacklist.txt")


def get_whitelist() -> List[str]:
    """
    Fetch the current whitelist from the file.
    """
    if not WHITELIST_PATH.exists():
        return []

    with open(WHITELIST_PATH, 'r') as f:
        return [line.strip() for line in f.readlines()]


def update_whitelist(entries: str) -> dict:
    """
    Add an entry to the whitelist file.
    """
    lines = entries.split('\n')
    with open(WHITELIST_PATH, 'w') as f:
        for line in lines:
            f.write(f"{line.strip()}\n")
    access_control.refresh_whitelist()
    return {"message": "Whitelist updated successfully."}


def get_blacklist() -> List[str]:
    """
    Fetch the current blacklist from the file.
    """
    if not BLACKLIST_PATH.exists():
        return []

    with open(BLACKLIST_PATH, 'r') as f:
        return [line.strip() for line in f.readlines()]


def update_blacklist(entries: str) -> dict:
    """
    Add an entry to the blacklist file.
    """
    lines = entries.split('\n')
    with open(BLACKLIST_PATH, 'w') as f:
        for line in lines:
            f.write(f"{line.strip()}\n")
    access_control.refresh_blacklist()
    return {"message": "Blacklist updated successfully."}