import json
import os
from pathlib import Path

try:
    import psycopg
except ImportError:
    psycopg = None


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
# History is project-scoped through project_id.
# =========================================================


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIRECTORY = PROJECT_ROOT / "data"

HISTORY_FILE = DATA_DIRECTORY / "scan_history.json"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    ""
).strip()

USE_DATABASE = bool(
    DATABASE_URL
)
DATABASE_INITIALIZED = False

# =========================================================
# PROJECT ID
# =========================================================

def normalize_project_id(project_id):
    """
    Convert a project identifier into a stable comparable value.
    """

    if project_id is None:
        return ""

    return str(
        project_id
    ).strip().replace(
        "\\",
        "/"
    ).strip("/").strip().lower()

def get_project_id(scan):
    """
    Get the project identity stored inside a scan.

    Existing scans may not have project_id, so fall back
    to target for backward compatibility.
    """

    project_id = scan.get(
        "project_id"
    )

    if project_id:
        return normalize_project_id(
            project_id
        )

    target = scan.get(
        "target"
    )

    if target:
        return normalize_project_id(
            target
        )

    return ""


# =========================================================
# JSON STORAGE INITIALIZATION
# =========================================================

def initialize_json_history():

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

    global DATABASE_INITIALIZED

    if not USE_DATABASE:
        return

    if DATABASE_INITIALIZED:
        return
    
    with psycopg.connect(
        DATABASE_URL
    ) as connection:

        with connection.cursor() as cursor:

            # -------------------------------------------------
            # CREATE TABLE
            # -------------------------------------------------

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id BIGSERIAL PRIMARY KEY,
                    scan_id TEXT UNIQUE NOT NULL,
                    project_id TEXT,
                    scan_time TEXT NOT NULL,
                    scan_data JSONB NOT NULL
                )
                """
            )

            # -------------------------------------------------
            # MIGRATE EXISTING DATABASES
            # -------------------------------------------------

            cursor.execute(
                """
                ALTER TABLE scan_history
                ADD COLUMN IF NOT EXISTS project_id TEXT
                """
            )

            # -------------------------------------------------
            # BACKFILL PROJECT IDS
            # -------------------------------------------------
            #
            # Existing scans were created before project_id
            # existed. Recover it from the stored target.
            # -------------------------------------------------

            cursor.execute(
                """
                UPDATE scan_history
                SET project_id = LOWER(
                    TRIM(
                        BOTH '/'
                        FROM COALESCE(
                            scan_data->>'project_id',
                            scan_data->>'target',
                            ''
                        )
                    )
                )
                WHERE project_id IS NULL
                   OR project_id = ''
                """
            )

            # -------------------------------------------------
            # PROJECT INDEX
            # -------------------------------------------------

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_scan_history_project
                ON scan_history (
                    project_id,
                    id DESC
                )
                """
            )

        connection.commit()

        DATABASE_INITIALIZED = True


# =========================================================
# LOAD JSON HISTORY
# =========================================================

def load_json_history():

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

def load_history(
    project_id=None
):

    """
    Load scan history.

    project_id=None:
        return all history.

    project_id=<value>:
        return only that project's history.

    History remains newest first.
    """

    normalized_project_id = normalize_project_id(
        project_id
    )

    # =====================================================
    # POSTGRESQL
    # =====================================================

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                if normalized_project_id:

                    cursor.execute(
                        """
                        SELECT scan_data
                        FROM scan_history
                        WHERE project_id = %s
                        ORDER BY id DESC
                        """,
                        (
                            normalized_project_id,
                        )
                    )

                else:

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

    # =====================================================
    # LOCAL JSON
    # =====================================================

    history = load_json_history()

    if not normalized_project_id:

        return history

    return [
        scan
        for scan in history
        if get_project_id(scan)
        == normalized_project_id
    ]


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(
    history
):

    """
    Save complete history.

    Maintains compatibility with the existing API.
    """

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    "DELETE FROM scan_history"
                )

                for scan in reversed(
                    history
                ):

                    project_id = get_project_id(
                        scan
                    )

                    cursor.execute(
                        """
                        INSERT INTO scan_history (
                            scan_id,
                            project_id,
                            scan_time,
                            scan_data
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s::jsonb
                        )
                        ON CONFLICT (scan_id)
                        DO UPDATE SET
                            project_id =
                                EXCLUDED.project_id,
                            scan_time =
                                EXCLUDED.scan_time,
                            scan_data =
                                EXCLUDED.scan_data
                        """,
                        (
                            scan.get(
                                "scan_id"
                            ),
                            project_id,
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

    save_json_history(
        history
    )


# =========================================================
# ADD SCAN
# =========================================================

def add_scan(
    scan
):

    """
    Add a new scan to history.

    The project_id is automatically derived from
    scan["project_id"] or scan["target"].
    """

    project_id = get_project_id(
        scan
    )

    # Add project_id to the stored scan itself.

    scan["project_id"] = project_id

    # =====================================================
    # POSTGRESQL
    # =====================================================

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
                        project_id,
                        scan_time,
                        scan_data
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s::jsonb
                    )
                    ON CONFLICT (scan_id)
                    DO UPDATE SET
                        project_id =
                            EXCLUDED.project_id,
                        scan_time =
                            EXCLUDED.scan_time,
                        scan_data =
                            EXCLUDED.scan_data
                    """,
                    (
                        scan.get(
                            "scan_id"
                        ),
                        project_id,
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

        return scan

    # =====================================================
    # LOCAL JSON
    # =====================================================

    history = load_json_history()

    history.insert(
    0,
    scan
)

# -------------------------------------------------
# Keep maximum 100 scans PER PROJECT
# -------------------------------------------------

    project_history = [
    item
        for item in history
        if get_project_id(item) == project_id
]

    other_history = [
    item
        for item in history
        if get_project_id(item) != project_id
]



    history = project_history + other_history

    save_json_history(
    history
)

    return scan
# =========================================================
# GET HISTORY
# =========================================================

def get_history(
    project_id=None
):

    return load_history(
        project_id
    )


# =========================================================
# GET SINGLE SCAN
# =========================================================

def get_scan(
    scan_id,
    project_id=None
):

    normalized_project_id = normalize_project_id(
        project_id
    )

    # =====================================================
    # POSTGRESQL
    # =====================================================

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                if normalized_project_id:

                    cursor.execute(
                        """
                        SELECT scan_data
                        FROM scan_history
                        WHERE scan_id = %s
                          AND project_id = %s
                        LIMIT 1
                        """,
                        (
                            scan_id,
                            normalized_project_id,
                        )
                    )

                else:

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

    # =====================================================
    # LOCAL JSON
    # =====================================================

    history = load_json_history()

    for scan in history:

        if scan.get(
            "scan_id"
        ) != scan_id:

            continue

        if normalized_project_id:

            if (
                get_project_id(scan)
                != normalized_project_id
            ):

                continue

        return scan

    return None


# =========================================================
# CLEAR HISTORY
# =========================================================

def clear_history(
    project_id=None
):

    normalized_project_id = normalize_project_id(
        project_id
    )

    # =====================================================
    # POSTGRESQL
    # =====================================================

    if USE_DATABASE:

        initialize_database()

        with psycopg.connect(
            DATABASE_URL
        ) as connection:

            with connection.cursor() as cursor:

                if normalized_project_id:

                    cursor.execute(
                        """
                        DELETE FROM scan_history
                        WHERE project_id = %s
                        """,
                        (
                            normalized_project_id,
                        )
                    )

                else:

                    cursor.execute(
                        "DELETE FROM scan_history"
                    )

            connection.commit()

        return

    # =====================================================
    # LOCAL JSON
    # =====================================================

    if not normalized_project_id:

        save_json_history(
            []
        )

        return

    history = load_json_history()

    remaining_history = [
        scan
        for scan in history
        if get_project_id(scan)
        != normalized_project_id
    ]

    save_json_history(
        remaining_history
    )