# =========================================================
# SECUVANTA LIVE EVENT STORE
# =========================================================

import json
import threading
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DATA_DIRECTORY = (
    PROJECT_ROOT / "data"
)

EVENT_FILE = (
    DATA_DIRECTORY /
    "live_events.json"
)

MAX_EVENTS = 100

_LOCK = threading.Lock()


# =========================================================
# INITIALIZE
# =========================================================

def initialize_events():

    DATA_DIRECTORY.mkdir(
        exist_ok=True
    )

    if not EVENT_FILE.exists():

        EVENT_FILE.write_text(
            "[]",
            encoding="utf-8"
        )


# =========================================================
# LOAD
# =========================================================

def load_events():

    initialize_events()

    with _LOCK:

        try:

            content = EVENT_FILE.read_text(
                encoding="utf-8"
            )

            events = json.loads(
                content
            )

            if isinstance(events, list):
                return events

        except (
            OSError,
            json.JSONDecodeError,
        ):

            pass

        return []


# =========================================================
# SAVE
# =========================================================

def save_events(events):

    initialize_events()

    with _LOCK:

        EVENT_FILE.write_text(
            json.dumps(
                events,
                indent=2,
            ),
            encoding="utf-8"
        )


# =========================================================
# ADD EVENT
# =========================================================

def add_live_event(
    event,
    event_id=None,
):

    events = load_events()

    safe_event = dict(event)

    safe_event.setdefault(
        "timestamp",
        datetime.now().isoformat(),
    )

    if event_id:
        safe_event["event_id"] = event_id

    events.insert(
        0,
        safe_event,
    )

    events = events[
        :MAX_EVENTS
    ]

    save_events(
        events
    )

    return safe_event


# =========================================================
# GET EVENTS
# =========================================================

def get_live_events(
    limit=25,
):

    events = load_events()

    return events[
        :max(1, min(
            int(limit),
            MAX_EVENTS,
        ))
    ]


# =========================================================
# CLEAR EVENTS
# =========================================================

def clear_live_events():

    save_events(
        []
    )