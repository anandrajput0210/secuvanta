from pathlib import Path

from core.detectors import detect_secrets


# =========================================================
# FILE TYPES
# =========================================================

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".txt",
    ".md",
    ".html",
    ".css",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bat",
    ".ps1",
    ".toml",
    ".properties",
}


SPECIAL_FILENAMES = {
    "dockerfile",
    "makefile",
    "jenkinsfile",
    "procfile",
    "gemfile",
    "rakefile",
}


# =========================================================
# IGNORED DIRECTORIES
# =========================================================

IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".sentinelzero_backups",
}


# =========================================================
# LIMITS
# =========================================================

MAX_FILE_SIZE = 5 * 1024 * 1024


# =========================================================
# TEXT FILE DETECTION
# =========================================================

def is_text_file(file_path: Path) -> bool:

    if file_path.name.startswith(".env"):
        return True

    if file_path.name.lower() in SPECIAL_FILENAMES:
        return True

    return file_path.suffix.lower() in TEXT_EXTENSIONS


# =========================================================
# IGNORE RULE
# =========================================================

def should_ignore(file_path: Path) -> bool:

    return any(
        part.lower() in IGNORED_DIRECTORIES
        for part in file_path.parts
    )


# =========================================================
# SCAN SINGLE FILE
# =========================================================

def scan_file(
    file_path: Path,
    fingerprint_file_path: str | None = None,
):
    """
    Scan one file and return:
        findings,
        status,
        reason
    """

    try:

        file_path = Path(file_path)

    except OSError as error:

        return (
            [],
            "FAILED",
            f"Unable to access file: {error}",
        )
        # -----------------------------------------------------
    # FILE SIZE
    # -----------------------------------------------------

    try:

        file_size = file_path.stat().st_size

    except OSError as error:

        return (
            [],
            "FAILED",
            f"Unable to access file: {error}",
        )

    # -----------------------------------------------------
    # LARGE FILE
    # -----------------------------------------------------

    if file_size > MAX_FILE_SIZE:

        return (
            [],
            "SKIPPED",
            "File exceeds 5 MB scan limit.",
        )


    # -----------------------------------------------------
    # READ FILE
    # -----------------------------------------------------

    try:

        try:

            text = file_path.read_text(
                encoding="utf-8"
            )

        except UnicodeDecodeError:

            text = file_path.read_text(
                encoding="latin-1"
            )

    except (OSError, PermissionError) as error:

        return (
            [],
            "FAILED",
            f"Unable to read file: {error}",
        )


    # -----------------------------------------------------
    # DETECT
    # -----------------------------------------------------

    try:

        findings = detect_secrets(
            text,
            str(file_path),
            fingerprint_file_path,
        )

    except Exception as error:

        return (
            [],
            "FAILED",
            f"Detector error: {error}",
        )


    return (
        findings,
        "SCANNED",
        None,
    )


# =========================================================
# SCAN DIRECTORY
# =========================================================

def scan_directory(
    directory: str,
    fingerprint_root: str | None = None,
):

    root = Path(directory)


    # -----------------------------------------------------
    # VALIDATE TARGET
    # -----------------------------------------------------

    if not root.exists():

        raise FileNotFoundError(
            f"Directory not found: {directory}"
        )


    if not root.is_dir():

        raise NotADirectoryError(
            f"Not a directory: {directory}"
        )


    # -----------------------------------------------------
    # RESULTS
    # -----------------------------------------------------

    findings = []

    files_scanned = 0
    files_skipped = 0
    files_failed = 0

    skipped_files = []
    failed_files = []


    # -----------------------------------------------------
    # WALK FILES
    # -----------------------------------------------------

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue


        if should_ignore(file_path):
            continue


        if not is_text_file(file_path):
            continue

        logical_file_path = None

        if fingerprint_root is not None:

            fingerprint_root_path = Path(
                fingerprint_root
            ).resolve()

            try:

                relative_file = (
                    file_path.resolve()
                    .relative_to(
                        fingerprint_root_path
                    )
                )

                logical_file_path = (
                    relative_file.as_posix()
                )

            except ValueError:

                logical_file_path = (
                    file_path.name
                )

        file_findings, status, reason = (
            scan_file(
                file_path,
                logical_file_path,
            )
        )

        # -------------------------------------------------
        # SCANNED
        # -------------------------------------------------

        if status == "SCANNED":

            files_scanned += 1

            findings.extend(
                file_findings
            )


        # -------------------------------------------------
        # SKIPPED
        # -------------------------------------------------

        elif status == "SKIPPED":

            files_skipped += 1

            skipped_files.append({

                "file_path":
                    str(file_path),

                "reason":
                    reason,
            })


        # -------------------------------------------------
        # FAILED
        # -------------------------------------------------

        elif status == "FAILED":

            files_failed += 1

            failed_files.append({

                "file_path":
                    str(file_path),

                "reason":
                    reason,
            })


    # -----------------------------------------------------
    # RETURN
    # -----------------------------------------------------

    return {
        "findings": findings,

        "files_scanned":
            files_scanned,

        "files_skipped":
            files_skipped,

        "files_failed":
            files_failed,

        "skipped_files":
            skipped_files,

        "failed_files":
            failed_files,
    }