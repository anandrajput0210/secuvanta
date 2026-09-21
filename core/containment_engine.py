# =========================================================
# SECUVANTA SAFE CONTAINMENT ENGINE
# Backup-first, reversible source containment
# =========================================================

from datetime import datetime
from pathlib import Path
import hashlib
import json
import shutil
import tempfile


# =========================================================
# BACKUP DIRECTORY
# =========================================================

BACKUP_DIRECTORY_NAME = ".sentinelzero_backups"


# =========================================================
# FILE HASH
# =========================================================

def calculate_file_hash(file_path: Path) -> str:
    """
    Calculate SHA-256 for verification.

    The file contents are not stored here.
    """

    digest = hashlib.sha256()

    with file_path.open(
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                64 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# =========================================================
# CREATE BACKUP
# =========================================================

def create_backup(
    file_path: str,
    project_root: str,
):
    """
    Create a timestamped backup of one file.

    Returns backup metadata.
    """

    source = Path(
        file_path
    ).resolve()

    root = Path(
        project_root
    ).resolve()


    if not source.exists():
        raise FileNotFoundError(
            f"File not found: {source}"
        )


    source.relative_to(root)


    backup_root = (
        root /
        BACKUP_DIRECTORY_NAME
    )

    backup_root.mkdir(
        exist_ok=True
    )


    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S_%f"
        )
    )


    relative_path = source.relative_to(
        root
    )


    backup_path = (
        backup_root /
        f"{timestamp}_{source.name}"
    )


    shutil.copy2(
        source,
        backup_path
    )


    return {
        "backup_path":
            str(backup_path),

        "original_path":
            str(source),

        "original_relative_path":
            str(relative_path),

        "original_hash":
            calculate_file_hash(
                source
            ),

        "timestamp":
            timestamp,
    }


# =========================================================
# SAFE SECRET CONTAINMENT
# =========================================================

def contain_secret(
    file_path: str,
    line_number: int,
    secret_value: str,
    project_root: str,
):
    """
    Replace one exact secret occurrence with a safe
    placeholder after creating a backup.

    This function is deliberately conservative.

    It:
        - requires an existing line
        - requires exact secret match
        - creates backup first
        - changes only one occurrence
        - preserves the rest of the file
    """

    source = Path(
        file_path
    ).resolve()

    root = Path(
        project_root
    ).resolve()


    source.relative_to(root)


    if not source.exists():
        raise FileNotFoundError(
            f"File not found: {source}"
        )


    if not secret_value:
        raise ValueError(
            "Secret value cannot be empty."
        )


    # -----------------------------------------------------
    # READ FILE
    # -----------------------------------------------------

    text = source.read_text(
        encoding="utf-8"
    )

    lines = text.splitlines(
        keepends=True
    )


    index = line_number - 1


    if index < 0 or index >= len(lines):

        raise ValueError(
            f"Invalid line number: {line_number}"
        )


    target_line = lines[index]


    # -----------------------------------------------------
    # VERIFY SECRET EXISTS
    # -----------------------------------------------------

    if secret_value not in target_line:

        raise ValueError(
            "Exact secret was not found "
            "on the specified line."
        )


    # -----------------------------------------------------
    # BACKUP FIRST
    # -----------------------------------------------------

    backup = create_backup(
        file_path=str(source),
        project_root=str(root),
    )


    # -----------------------------------------------------
    # CONTAIN
    # -----------------------------------------------------

    replacement = (
        "[REDACTED_BY_SECUVANTA]"
    )


    updated_line = target_line.replace(
        secret_value,
        replacement,
        1,
    )


    lines[index] = updated_line


    # -----------------------------------------------------
    # SAFE WRITE
    # -----------------------------------------------------

    temporary_file = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(source.parent),
            delete=False,
        ) as temp:

            temporary_file = Path(
                temp.name
            )

            temp.writelines(
                lines
            )

            temp.flush()


        temporary_file.replace(
            source
        )


    except Exception:

        if temporary_file and temporary_file.exists():

            temporary_file.unlink(
                missing_ok=True
            )

        raise


    # -----------------------------------------------------
    # VERIFY
    # -----------------------------------------------------

    new_hash = calculate_file_hash(
        source
    )


    return {
        "success": True,

        "action":
            "CONTAIN",

        "file_path":
            str(source),

        "line_number":
            line_number,

        "backup":
            backup,

        "new_hash":
            new_hash,

        "verification_required":
            True,
    }


# =========================================================
# ROLLBACK
# =========================================================

def rollback(
    containment_result,
):
    """
    Restore the exact backup created before containment.
    """

    backup = containment_result.get(
        "backup"
    )

    if not backup:
        raise ValueError(
            "Containment backup information missing."
        )


    source = Path(
        containment_result[
            "file_path"
        ]
    )


    backup_path = Path(
        backup[
            "backup_path"
        ]
    )


    if not backup_path.exists():

        raise FileNotFoundError(
            "Containment backup no longer exists."
        )


    shutil.copy2(
        backup_path,
        source
    )


    return {
        "success": True,

        "action":
            "ROLLBACK",

        "file_path":
            str(source),

        "restored_hash":
            calculate_file_hash(
                source
            ),
    }