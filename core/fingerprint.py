import hashlib
import os


def normalize_path(file_path: str) -> str:
    """
    Normalize a file path so equivalent paths
    produce the same representation.
    """

    path = os.path.normpath(file_path)

    return path.replace("\\", "/").lower()


def generate_fingerprint(
    finding_type: str,
    file_path: str,
    secret_value: str,
) -> str:
    """
    Generate a stable identifier for a security finding.

    The raw secret is used only in memory to create
    the SHA-256 fingerprint.

    The raw secret is NEVER returned or stored.
    """

    normalized_type = finding_type.strip().lower()

    normalized_path = normalize_path(
        file_path
    )

    identity_material = (
        f"{normalized_type}|"
        f"{normalized_path}|"
        f"{secret_value}"
    )

    return hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()