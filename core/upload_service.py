# =========================================================
# SECUVANTA SECURE PROJECT UPLOAD SERVICE
# =========================================================

import stat
import tempfile
import zipfile
from pathlib import Path


MAX_UPLOAD_SIZE = 25 * 1024 * 1024          # 25 MB
MAX_EXTRACTED_FILES = 5000
MAX_SINGLE_FILE_SIZE = 5 * 1024 * 1024      # 5 MB
MAX_TOTAL_EXTRACTED_SIZE = 50 * 1024 * 1024 # 50 MB
CHUNK_SIZE = 1024 * 1024                    # 1 MB


def _is_symlink(member: zipfile.ZipInfo) -> bool:
    """
    Detect symbolic-link entries in a ZIP archive.
    """
    file_mode = (member.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(file_mode)


def validate_zip_file(zip_path: Path) -> None:
    """
    Validate an uploaded ZIP before extraction.

    Checks:
        - ZIP exists
        - ZIP size is within the upload limit
        - ZIP can be opened
        - File count is reasonable
        - Individual files are not oversized
        - Total extracted size is reasonable
        - Paths cannot escape the extraction directory
        - Symbolic links are rejected
    """
    if not zip_path.exists():
        raise FileNotFoundError(
            "Uploaded ZIP file does not exist."
        )

    if zip_path.stat().st_size > MAX_UPLOAD_SIZE:
        raise ValueError(
            "Uploaded ZIP exceeds the maximum allowed size."
        )

    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            members = archive.infolist()

            if len(members) > MAX_EXTRACTED_FILES:
                raise ValueError(
                    "ZIP contains too many files."
                )
            seen_names = set()
            total_declared_size = 0

            for member in members:
                member_path = Path(member.filename)
                if member.filename in seen_names:
                    raise ValueError(
                        f"ZIP contains a duplicate entry: "
                        f"{member.filename}"
                    )

                seen_names.add(member.filename)
                if member.is_dir():
                    continue

                if _is_symlink(member):
                    raise ValueError(
                        f"ZIP contains an unsupported symbolic link: "
                        f"{member.filename}"
                    )

                if member.file_size > MAX_SINGLE_FILE_SIZE:
                    raise ValueError(
                        f"ZIP contains an oversized file: "
                        f"{member.filename}"
                    )

                total_declared_size += member.file_size

                if (
                    total_declared_size
                    > MAX_TOTAL_EXTRACTED_SIZE
                ):
                    raise ValueError(
                        "ZIP extracted content exceeds "
                        "the maximum allowed size."
                    )

                if member_path.is_absolute():
                    raise ValueError(
                        "ZIP contains an absolute path."
                    )

                if ".." in member_path.parts:
                    raise ValueError(
                        "ZIP contains an unsafe path."
                    )

    except zipfile.BadZipFile as exc:
        raise ValueError(
            "Uploaded file is not a valid ZIP archive."
        ) from exc


def extract_zip_safely(zip_path: Path) -> Path:
    """
    Validate and extract a ZIP into an isolated
    temporary directory.

    Extraction is performed in chunks so a malicious
    archive cannot force the whole file into memory.

    Returns:
        Path to the extracted project directory.
    """
    validate_zip_file(zip_path)

    temporary_directory = Path(
        tempfile.mkdtemp(
            prefix="secuvanta_upload_"
        )
    )

    extraction_root = (
        temporary_directory / "project"
    )

    extraction_root.mkdir(
        parents=True,
        exist_ok=True
    )

    total_extracted_size = 0

    try:
        with zipfile.ZipFile(
            zip_path,
            "r"
        ) as archive:

            for member in archive.infolist():

                destination = (
                    extraction_root
                    / member.filename
                ).resolve()

                extraction_root_resolved = (
                    extraction_root.resolve()
                )

                try:
                    destination.relative_to(
                        extraction_root_resolved
                    )
                except ValueError as exc:
                    raise ValueError(
                        "ZIP extraction path escaped "
                        "the temporary workspace."
                    ) from exc

                if member.is_dir():
                    destination.mkdir(
                        parents=True,
                        exist_ok=True
                    )
                    continue

                if _is_symlink(member):
                    raise ValueError(
                        f"ZIP contains an unsupported "
                        f"symbolic link: {member.filename}"
                    )

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                current_file_size = 0

                with archive.open(
                    member,
                    "r"
                ) as source:

                    with destination.open(
                        "wb"
                    ) as target:

                        while True:

                            chunk = source.read(
                                CHUNK_SIZE
                            )

                            if not chunk:
                                break

                            current_file_size += (
                                len(chunk)
                            )

                            total_extracted_size += (
                                len(chunk)
                            )

                            if (
                                current_file_size
                                > MAX_SINGLE_FILE_SIZE
                            ):
                                raise ValueError(
                                    f"Extracted file exceeds "
                                    f"the maximum allowed size: "
                                    f"{member.filename}"
                                )

                            if (
                                total_extracted_size
                                > MAX_TOTAL_EXTRACTED_SIZE
                            ):
                                raise ValueError(
                                    "ZIP extracted content "
                                    "exceeds the maximum "
                                    "allowed size."
                                )

                            target.write(chunk)

    except Exception:
        cleanup_upload(
            temporary_directory
        )
        raise

    return extraction_root


def cleanup_upload(
    temporary_directory: Path
) -> None:
    """
    Remove a temporary uploaded-project workspace.
    """
    if not temporary_directory.exists():
        return

    for path in sorted(
        temporary_directory.rglob("*"),
        reverse=True
    ):
        try:
            if path.is_file():
                path.unlink()

            elif path.is_dir():
                path.rmdir()

        except OSError:
            pass

    try:
        temporary_directory.rmdir()

    except OSError:
        pass