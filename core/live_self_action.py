# SECUVANTA LIVE SELF-ACTION TRACKER
# =========================================================

from pathlib import Path
from hashlib import sha256
from threading import Lock
from time import time


# =========================================================
# CONFIGURATION
# =========================================================

SELF_ACTION_TTL_SECONDS = 10.0


# =========================================================
# IN-MEMORY STATE
# =========================================================

_lock = Lock()

_pending_actions = {}


# =========================================================
# FILE HASH
# =========================================================

def calculate_file_hash(
    file_path: str,
):
    """
    Calculate SHA-256 for the current file.

    Returns None when the file cannot be read.
    """

    path = Path(file_path)

    try:

        data = path.read_bytes()

    except OSError:

        return None

    return sha256(data).hexdigest()


# =========================================================
# REGISTER SELF ACTION
# =========================================================

def register_self_action(
    file_path: str,
):
    """
    Register the current file state as a modification
    intentionally produced by SecuVanta.

    The state is kept only in memory.
    """

    path = str(
        Path(file_path).resolve()
    )

    file_hash = calculate_file_hash(
        path
    )

    if file_hash is None:
        return False

    with _lock:

        _pending_actions[path] = {
            "hash": file_hash,
            "timestamp": time(),
        }

    return True


# =========================================================
# CHECK / CONSUME SELF ACTION
# =========================================================

def consume_self_action(
    file_path: str,
):
    """
    Return True when the current file state matches a
    recent SecuVanta-generated modification.

    Matching actions are consumed once.
    """

    path = str(
        Path(file_path).resolve()
    )

    current_hash = calculate_file_hash(
        path
    )

    now = time()

    with _lock:

        action = _pending_actions.get(
            path
        )

        if action is None:
            return False

        if (
            now - action["timestamp"]
            > SELF_ACTION_TTL_SECONDS
        ):

            del _pending_actions[path]

            return False

        if (
            current_hash is not None
            and current_hash == action["hash"]
        ):

            del _pending_actions[path]

            return True

        return False