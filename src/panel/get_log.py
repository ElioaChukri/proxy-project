import os
from pathlib import Path
from typing import List

LOG_PATH = Path("../logs/app.log")


def get_logs(num_lines: int = 100) -> List[str]:
    """
    Fetch the last num_lines lines from the log file.
    """
    if not LOG_PATH.exists():
        return ["Log file does not exist."]

    with open(LOG_PATH, 'r') as f:
        logs = f.readlines()
        return logs[-num_lines:]
