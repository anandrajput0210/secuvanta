import json
import os
from pathlib import Path

import psycopg


# =========================================================
# SECUVANTA HISTORY STORAGE
# =========================================================
#
# Production:
#   DATABASE_URL -> PostgreSQL
#
# Local development:
#   No DATABASE_URL -> JSON file
#
# The public history API remains unchanged.
# =========================================================


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIRECTORY = PROJECT_ROOT / "data"

HISTORY_FILE = DATA_DIRECTORY / "scan_history.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    ""
).strip()


# =========================================================
# STORAGE MODE
# =========================================================

USE_DATABASE = bool(
    DATABASE_URL
)


# =========================================================
# JSON STORAGE INITIALIZATION
# =========================================================

def initialize_json_history():

    """
    Create the local data directory and history file
    when PostgreSQL is not being used.
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
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    """
    Create the PostgreSQL history table if it does not exist.
    """

    if not USE_DATABASE:
        return

    with psycopg.connect(
        DATABASE_URL
    ) as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id BIGSERIAL PRIMARY KEY,
                    scan_id TEXT UNIQUE NOT NULL,
                    scan_time TEXT NOT NULL,
                    scan_data JSONB NOT NULL
                )
                """
            )

        connection.commit()


# =========================================================
# LOAD JSON HISTORY
# =========================================================

def load_json_history():

    """
    Load history from the local JSON file.
    """

    initialize_json_history()

    try:

        content = HISTORY_FILE.read_text(
            encoding="utf-8"
        )

        history = json.loads(
            content
        )

        if isinstance(
            history,
            list
        ):

            return history

        return []

    except json.JSONDecodeError as error:

        print(
            f"HISTORY JSON ERROR: {error}"
        )

        return []

    except OSError as error:

        print(
            f"HISTORY FILE ERROR: {error}"
        )

        return []


# =========================================================
# SAVE JSON HISTORY
# =========================================================

def save_json_history(history):

    """
    Save complete history to the local JSON file.
    """

    initialize_json_history()

    HISTORY_FILE.write_text(

        json.dumps(
            history,
            indent=4
        ),

        encoding="utf-8"
    )


# =========================================================
# LOAD HISTORY
# =========================================================

def load_history():

    """
    Load all previous scan records.
    """

    # -----------------------------------------------------
    # POSTGRESQL
    # -----------------------------------------------------

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT scan_data
                    FROM scan_history
                    ORDER BY id DESC
                    """
                )

                rows = cursor.fetchall()

        history = []

        for row in rows:

            scan_data = row[0]

            if isinstance(
                scan_data,
                dict
            ):

                history.append(
                    scan_data
                )

            elif isinstance(
                scan_data,
                str
            ):

                try:

                    decoded = json.loads(
                        scan_data
                    )

                    if isinstance(
                        decoded,
                        dict
                    ):

                        history.append(
                            decoded
                        )

                except json.JSONDecodeError:

                    continue

        return history


    # -----------------------------------------------------
    # LOCAL JSON
    # -----------------------------------------------------

    return load_json_history()


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(history):

    """
    Save complete history.

    Used by JSON mode.
    PostgreSQL mode saves individual scans through add_scan().
    """

    if USE_DATABASE:

        initialize_database()

        # Replace the database history with the supplied list.
        # This is mainly useful for compatibility with clear_history()
        # and any existing callers.

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    "DELETE FROM scan_history"
                )

                for scan in reversed(
                    history[:100]
                ):

                    cursor.execute(
                        """
                        INSERT INTO scan_history (
                            scan_id,
                            scan_time,
                            scan_data
                        )
                        VALUES (
                            %s,
                            %s,
                            %s::jsonb
                        )
                        ON CONFLICT (scan_id)
                        DO UPDATE SET
                            scan_time = EXCLUDED.scan_time,
                            scan_data = EXCLUDED.scan_data
                        """,
                        (
                            scan.get(
                                "scan_id"
                            ),
                            scan.get(
                                "scan_time",
                                ""
                            ),
                            json.dumps(
                                scan
                            )
                        )
                    )

            connection.commit()

        return


    # Local JSON mode

    save_json_history(
        history
    )


# =========================================================
# ADD SCAN
# =========================================================

def add_scan(scan):

    """
    Add a new scan to history.

    Newest scans remain first.
    Maximum history size is 100.
    """

    # -----------------------------------------------------
    # POSTGRESQL
    # -----------------------------------------------------

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    INSERT INTO scan_history (
                        scan_id,
                        scan_time,
                        scan_data
                    )
                    VALUES (
                        %s,
                        %s,
                        %s::jsonb
                    )
                    ON CONFLICT (scan_id)
                    DO UPDATE SET
                        scan_time = EXCLUDED.scan_time,
                        scan_data = EXCLUDED.scan_data
                    """,
                    (
                        scan.get(
                            "scan_id"
                        ),
                        scan.get(
                            "scan_time",
                            ""
                        ),
                        json.dumps(
                            scan
                        )
                    )
                )

                # Keep only the latest 100 scans.

                cursor.execute(
                    """
                    DELETE FROM scan_history
                    WHERE id NOT IN (
                        SELECT id
                        FROM scan_history
                        ORDER BY id DESC
                        LIMIT 100
                    )
                    """
                )

            connection.commit()

        return scan


    # -----------------------------------------------------
    # LOCAL JSON
    # -----------------------------------------------------

    history = load_json_history()

    history.insert(
        0,
        scan
    )

    history = history[:100]

    save_json_history(
        history
    )

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

    # -----------------------------------------------------
    # POSTGRESQL
    # -----------------------------------------------------

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT scan_data
                    FROM scan_history
                    WHERE scan_id = %s
                    LIMIT 1
                    """,
                    (
                        scan_id,
                    )
                )

                row = cursor.fetchone()

        if row is None:

            return None

        scan_data = row[0]

        if isinstance(
            scan_data,
            dict
        ):

            return scan_data

        if isinstance(
            scan_data,
            str
        ):

            try:

                decoded = json.loads(
                    scan_data
                )

                if isinstance(
                    decoded,
                    dict
                ):

                    return decoded

            except json.JSONDecodeError:

                return None

        return None


    # -----------------------------------------------------
    # LOCAL JSON
    # -----------------------------------------------------

    history = load_json_history()

    for scan in history:

        if scan.get(
            "scan_id"
        ) == scan_id:

            return scan

    return None


# =========================================================
# CLEAR HISTORY
# =========================================================

def clear_history():

    """
    Remove all scan history.
    """

    # -----------------------------------------------------
    # POSTGRESQL
    # -----------------------------------------------------

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    "DELETE FROM scan_history"
                )

            connection.commit()

        return


    # -----------------------------------------------------
    # LOCAL JSON
    # -----------------------------------------------------

    save_json_history(
        []
    )