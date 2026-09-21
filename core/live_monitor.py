# =========================================================
# SECUVANTA LIVE MONITOR
# Project-scoped filesystem monitoring
# =========================================================

import time
from pathlib import Path
from core.scanner import should_ignore

# =========================================================
# DEFAULT SETTINGS
# =========================================================

DEFAULT_INTERVAL = 1.0


# =========================================================
# FILE SNAPSHOT
# =========================================================

def build_snapshot(root: Path):
    """
    Build a lightweight snapshot of files in the project.

    Stores:
        relative path
        modification time
        file size

    No file contents are stored here.
    """

    snapshot = {}

    if not root.exists() or not root.is_dir():
        return snapshot

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if should_ignore(file_path):
            continue

        try:
            stat = file_path.stat()
        except OSError:
            continue

        relative_path = file_path.relative_to(root)

        snapshot[str(relative_path)] = (
        stat.st_mtime_ns,
        stat.st_size,
    )

    return snapshot


# =========================================================
# DETECT CHANGES
# =========================================================

def detect_changes(
    previous_snapshot,
    current_snapshot,
):
    """
    Return created, modified and deleted files.
    """

    previous_files = set(
        previous_snapshot.keys()
    )

    current_files = set(
        current_snapshot.keys()
    )


    created = sorted(
        current_files - previous_files
    )

    deleted = sorted(
        previous_files - current_files
    )


    modified = sorted(
        path
        for path in (
            previous_files & current_files
        )
        if previous_snapshot[path]
        != current_snapshot[path]
    )


    return {
        "created": created,
        "modified": modified,
        "deleted": deleted,
    }


# =========================================================
# WATCH ONCE
# =========================================================

def check_for_changes(root: Path, snapshot):
    """
    Build a new snapshot and compare it with the old one.
    """

    current_snapshot = build_snapshot(
        root
    )

    changes = detect_changes(
        snapshot,
        current_snapshot,
    )

    return (
        current_snapshot,
        changes,
    )


# =========================================================
# EVENT CALLBACK
# =========================================================

def process_change(
    root: Path,
    relative_path: str,
    event_type: str,
):
    """
    Handle one filesystem event.

    This function intentionally does NOT modify files.

    It returns event information so the protection layer
    can decide what should happen.
    """

    file_path = root / relative_path

    return {
        "event": event_type,
        "file_path": str(file_path),
        "exists": file_path.exists(),
        "timestamp": time.time(),
    }


# =========================================================
# LIVE WATCH LOOP
# =========================================================

def watch(
    directory: str,
    on_change=None,
    interval: float = DEFAULT_INTERVAL,
):
    """
    Watch a project directory until interrupted.

    on_change receives:

        {
            "event": "CREATED" | "MODIFIED" | "DELETED",
            "file_path": "...",
            "exists": True | False,
            "timestamp": ...
        }

    This monitor performs no automatic remediation.
    """

    root = Path(directory).resolve()


    if not root.exists():
        raise FileNotFoundError(
            f"Directory not found: {directory}"
        )


    if not root.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {directory}"
        )


    snapshot = build_snapshot(
        root
    )


    print(
        f"SecuVanta live monitor started: {root}"
    )


    try:

        while True:

            time.sleep(interval)


            new_snapshot, changes = (
                check_for_changes(
                    root,
                    snapshot,
                )
            )


            # ---------------------------------------------
            # CREATED
            # ---------------------------------------------

            for relative_path in changes["created"]:

                event = process_change(
                    root,
                    relative_path,
                    "CREATED",
                )

                if on_change:
                    on_change(event)


            # ---------------------------------------------
            # MODIFIED
            # ---------------------------------------------

            for relative_path in changes["modified"]:

                event = process_change(
                    root,
                    relative_path,
                    "MODIFIED",
                )

                if on_change:
                    on_change(event)


            # ---------------------------------------------
            # DELETED
            # ---------------------------------------------

            for relative_path in changes["deleted"]:

                event = process_change(
                    root,
                    relative_path,
                    "DELETED",
                )

                if on_change:
                    on_change(event)


            snapshot = new_snapshot


    except KeyboardInterrupt:

        print(
            "\nSecuVanta live monitor stopped."
        )