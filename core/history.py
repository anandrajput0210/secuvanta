import json
from pathlib import Path


# =========================================================
# HISTORY STORAGE
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIRECTORY = PROJECT_ROOT / "data"

HISTORY_FILE = DATA_DIRECTORY / "scan_history.json"


# =========================================================
# INITIALIZE STORAGE
# =========================================================

def initialize_history():

    """
    Create the data directory and history file
    if they do not already exist.
    """

    DATA_DIRECTORY.mkdir(
        exist_ok=True
    )

    if not HISTORY_FILE.exists():

        HISTORY_FILE.write_text(
            "[]",
            encoding="utf-8"
        )


# =========================================================
# LOAD HISTORY
# =========================================================

def load_history():

    """
    Load all previous scan records.
    """

    initialize_history()

    try:

        content = HISTORY_FILE.read_text(
            encoding="utf-8"
        )

        history = json.loads(content)

        if isinstance(history, list):

            return history

        return []

    except json.JSONDecodeError as error:

        print(f"HISTORY JSON ERROR: {error}")

        return []

    except OSError as error:

        print(f"HISTORY FILE ERROR: {error}")

    return []


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(history):

    """
    Save the complete scan history.
    """

    initialize_history()

    HISTORY_FILE.write_text(

        json.dumps(
            history,
            indent=4
        ),

        encoding="utf-8"
    )


# =========================================================
# ADD SCAN
# =========================================================

def add_scan(scan):

    """
    Add a new scan to history.
    """

    history = load_history()

    # Newest scans first
    history.insert(
        0,
        scan
    )

    # Keep the latest 100 scans
    history = history[:100]

    save_history(history)

    return scan


# =========================================================
# GET HISTORY
# =========================================================

def get_history():

    """
    Return all stored scan history.
    """

    return load_history()


# =========================================================
# GET SINGLE SCAN
# =========================================================

def get_scan(scan_id):

    """
    Find one scan using its scan ID.
    """

    history = load_history()

    for scan in history:

        if scan.get("scan_id") == scan_id:

            return scan

    return None


# =========================================================
# CLEAR HISTORY
# =========================================================

def clear_history():

    """
    Remove all scan history.
    """

    save_history([])