# =========================================================
# SECUVANTA AUTO PROTECTION ENGINE
# =========================================================

from pathlib import Path

from core.containment_engine import (
    contain_secret,
    rollback,
)

from core.detectors import (
    recover_secret_for_fingerprint,
)

from core.scanner import (
    scan_file,
)


# =========================================================
# PROTECT ONE FINDING
# =========================================================

def protect_finding(
    finding,
    project_root: str,
):
    """
    Safely contain one finding.

    Workflow:

        recover exact secret
            ↓
        backup
            ↓
        contain
            ↓
        rescan
            ↓
        verify target is gone
            ↓
        keep OR rollback

    Fails closed if anything is uncertain.
    """

    source = Path(
        finding.file_path
    ).resolve()

    root = Path(
        project_root
    ).resolve()


    # =====================================================
    # PATH SAFETY
    # =====================================================

    try:

        source.relative_to(
            root
        )

    except ValueError:

        return {
            "success": False,
            "action": "BLOCKED",
            "reason": (
                "Target file is outside "
                "the protected project."
            ),
        }


    if not source.exists():

        return {
            "success": False,
            "action": "BLOCKED",
            "reason": "Target file no longer exists.",
        }


    # =====================================================
    # READ CURRENT FILE
    # =====================================================

    try:

        text = source.read_text(
            encoding="utf-8"
        )

    except (OSError, UnicodeDecodeError) as error:

        return {
            "success": False,
            "action": "BLOCKED",
            "reason": (
                f"Unable to safely read target file: "
                f"{error}"
            ),
        }


    # =====================================================
    # RECOVER SECRET EPHEMERALLY
    # =====================================================
    secret = recover_secret_for_fingerprint(
        text=text,
        file_path=finding.file_path,
        target_fingerprint=finding.fingerprint,
    )   


    # -----------------------------------------------------
    # FAIL CLOSED
    # -----------------------------------------------------

    if secret is None:

        return {
            "success": False,
            "action": "BLOCKED",
            "reason": (
                "Exact secret could not be safely "
                "recovered from the current file."
            ),
        }


    # =====================================================
    # CONTAIN
    # =====================================================

    try:

        containment = contain_secret(
            file_path=str(source),

            line_number=finding.line_number,

            secret_value=secret,

            project_root=str(root),
        )

    except Exception as error:

        return {
            "success": False,
            "action": "FAILED",
            "reason": (
                f"Containment failed: {error}"
            ),
        }


    # =====================================================
    # IMMEDIATE RESCAN
    # =====================================================

    try:

        rescanned_findings, status, reason = (
            scan_file(source)
        )

    except Exception as error:

        # -------------------------------------------------
        # Verification failed → rollback
        # -------------------------------------------------

        rollback(
            containment
        )

        return {
            "success": False,
            "action": "ROLLED_BACK",
            "reason": (
                f"Verification scan failed: "
                f"{error}"
            ),
        }


    # =====================================================
    # SCAN FAILURE
    # =====================================================

    if status != "SCANNED":

        rollback(
            containment
        )

        return {
            "success": False,
            "action": "ROLLED_BACK",
            "reason": (
                "Verification scan could not "
                "complete safely."
            ),
        }


    # =====================================================
    # VERIFY TARGET FINDING IS GONE
    # =====================================================

    remaining_fingerprints = {

        result.fingerprint

        for result in rescanned_findings

        if result.fingerprint
    }


    if finding.fingerprint in (
        remaining_fingerprints
    ):

        rollback(
            containment
        )

        return {
            "success": False,
            "action": "ROLLED_BACK",
            "reason": (
                "Target exposure remained after "
                "containment verification."
            ),
        }


    # =====================================================
    # SUCCESS
    # =====================================================

    return {

        "success": True,

        "action":
            "CONTAINED",

        "file_path":
            str(source),

        "line_number":
            finding.line_number,

        "backup":
            containment["backup"],

        "verification":
            "PASSED",

        "remaining_findings":
            len(rescanned_findings),

        "reason":
            (
                "Target exposure was contained and "
                "verified by a follow-up scan."
            ),
    }