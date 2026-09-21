# =========================================================
# SECUVANTA LIVE DETECTION BRIDGE
# =========================================================

from pathlib import Path

from core.scanner import is_text_file
from core.scanner import should_ignore
from core.scanner import scan_file

from core.risk_engine import calculate_finding_risk

from core.protection_policy import decide_action


def analyze_changed_file(
    file_path: str,
    protection_mode: str,
):
    """
    Analyze one changed file through the complete
    detection → intelligence → policy pipeline.

    IMPORTANT:
    This function does not modify the file.
    """

    path = Path(file_path)


    # =====================================================
    # BASIC VALIDATION
    # =====================================================

    if not path.exists():

        return {
            "success": True,
            "event": "DELETED",
            "file_path": str(path),
            "findings": [],
            "decisions": [],
        }


    if not path.is_file():

        return {
            "success": False,
            "error": "Changed path is not a file.",
        }


    if should_ignore(path):

        return {
            "success": True,
            "event": "IGNORED",
            "file_path": str(path),
            "findings": [],
            "decisions": [],
        }


    if not is_text_file(path):

        return {
            "success": True,
            "event": "NON_TEXT_FILE",
            "file_path": str(path),
            "findings": [],
            "decisions": [],
        }


    # =====================================================
    # SCAN FILE
    # =====================================================

    findings, status, reason = scan_file(path)


    if status != "SCANNED":

        return {
            "success": False,
            "event": status,
            "file_path": str(path),
            "error": reason,
            "findings": [],
            "decisions": [],
        }


    # =====================================================
    # ANALYZE FINDINGS
    # =====================================================

    decisions = []


    for finding in findings:

        intelligence = calculate_finding_risk(
            finding
        )


        policy = decide_action(

            mode=protection_mode,

            severity=finding.severity,

            confidence=intelligence[
                "confidence"
            ],

            exposure=intelligence[
                "exposure"
            ],

            false_positive_risk=intelligence[
                "false_positive_risk"
            ],
        )


        decisions.append({

            "finding": finding,

            "intelligence":
                intelligence,

            "policy":
                policy,
        })


    # =====================================================
    # RESULT
    # =====================================================

    return {

        "success": True,

        "event": "ANALYZED",

        "file_path":
            str(path),

        "findings":
            findings,

        "decisions":
            decisions,
    }