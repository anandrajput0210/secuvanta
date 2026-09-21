from dataclasses import dataclass, asdict
from typing import Optional


# =========================================================
# FINDING STATUS
# =========================================================

OPEN = "OPEN"
IGNORED = "IGNORED"
RESOLVED = "RESOLVED"


# =========================================================
# FINDING LIFECYCLE
# =========================================================

NEW = "NEW"
PERSISTENT = "PERSISTENT"
REAPPEARED = "REAPPEARED"
LIFECYCLE_RESOLVED = "RESOLVED"


# =========================================================
# SECURITY FINDING
# =========================================================

@dataclass
class Finding:
    """
    Represents a security finding discovered during a scan.

    The `value` field must ALWAYS contain a masked value.
    Raw secrets must never be stored in this object.
    """

    # Required fields
    finding_type: str
    severity: str
    file_path: str
    line_number: int
    value: str
    description: str

        # Optional detector evidence
    entropy: Optional[float] = None

    # Stable identity
    fingerprint: Optional[str] = None

    # Context-aware security analysis
    exposure: str = "MEDIUM"
    exposure_score: int = 50
    context_reasons: list[str] | None = None
    variable_name: Optional[str] = None

    # Current status
    status: str = OPEN

    # Cross-scan lifecycle
    lifecycle: str = NEW

    # Historical tracking
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    times_seen: int = 1

    # Optional reason when ignored
    status_reason: Optional[str] = None

    def to_dict(self):
        """Convert finding to a dictionary."""
        return asdict(self)


# =========================================================
# SCAN RESULT
# =========================================================

@dataclass
class ScanResult:
    """
    Represents the complete result of a SecuVanta scan.
    """

    findings: list
    files_scanned: int
    files_skipped: int
    files_failed: int
    scan_duration: float = 0.0

    def to_dict(self):
        """Convert scan result to a dictionary."""
        return {
            "findings": [
                finding.to_dict()
                if hasattr(finding, "to_dict")
                else finding
                for finding in self.findings
            ],
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "scan_duration": self.scan_duration,
        }