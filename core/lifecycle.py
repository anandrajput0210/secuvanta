from datetime import datetime

from core.models import (
    OPEN,
    IGNORED,
    RESOLVED,
    NEW,
    PERSISTENT,
    REAPPEARED,
    LIFECYCLE_RESOLVED,
)


def now_iso():
    """Return the current timestamp."""
    return datetime.now().isoformat()


def index_findings(findings):
    """
    Create a fingerprint -> finding mapping.
    """
    return {
        finding.get("fingerprint"): finding
        for finding in findings
        if finding.get("fingerprint")
    }


def analyze_lifecycle(
    previous_findings,
    current_findings,
    historical_findings=None,
):
    """
    Compare current findings with the immediately previous scan while also
    consulting the most recent historical state of each fingerprint.

    Lifecycle states:
        NEW         - fingerprint has never been seen before
        PERSISTENT  - fingerprint was active in the immediately previous scan
        REAPPEARED  - fingerprint was previously resolved and has returned
        RESOLVED    - fingerprint was active in the previous scan but is absent now

    ``historical_findings`` is expected to contain the most recent prior state
    for each fingerprint.  It is optional for backwards compatibility; when
    omitted, behavior falls back to adjacent-scan analysis.
    """

    previous = index_findings(previous_findings or [])
    current = index_findings(current_findings or [])
    historical = index_findings(historical_findings or [])

    current_time = now_iso()

    new_count = 0
    persistent_count = 0
    reappeared_count = 0
    resolved_count = 0

    # =====================================================
    # CURRENT FINDINGS
    # =====================================================

    for fingerprint, finding in current.items():

        previous_finding = previous.get(fingerprint)
        historical_finding = historical.get(fingerprint)

        # -------------------------------------------------
        # FINDING WAS IN THE IMMEDIATELY PREVIOUS SCAN
        # -------------------------------------------------

        if previous_finding is not None:

            previous_status = previous_finding.get(
                "status",
                OPEN,
            )

            previous_times_seen = previous_finding.get(
                "times_seen",
                1,
            )

            finding["first_seen"] = (
                previous_finding.get("first_seen")
                or current_time
            )

            finding["last_seen"] = current_time

            finding["times_seen"] = previous_times_seen + 1

            # A finding still present in the previous scan is persistent.
            # A resolved state should normally only come from historical state
            # when the finding was absent in the immediately previous scan.
            finding["lifecycle"] = PERSISTENT
            persistent_count += 1

            if previous_status == IGNORED:
                finding["status"] = IGNORED
                finding["status_reason"] = previous_finding.get(
                    "status_reason"
                )
            else:
                finding["status"] = OPEN

            continue

        # -------------------------------------------------
        # FINDING WAS NOT IN THE IMMEDIATELY PREVIOUS SCAN
        # -------------------------------------------------

        # Use the most recent historical state to distinguish NEW from
        # REAPPEARED.  This is the crucial missing piece in the old logic.
        if (
            historical_finding is not None
            and historical_finding.get("status") == RESOLVED
        ):
            finding["lifecycle"] = REAPPEARED
            finding["first_seen"] = (
                historical_finding.get("first_seen")
                or current_time
            )
            finding["times_seen"] = (
                historical_finding.get("times_seen", 1) + 1
            )
            finding["status"] = OPEN
            finding["last_seen"] = current_time
            reappeared_count += 1

        elif historical_finding is not None:
            # The fingerprint was seen before, but its latest known state is
            # not resolved. This normally indicates that the historical input
            # is incomplete, so preserve its history without claiming a new
            # finding. In normal server flow, adjacent previous findings handle
            # the persistent case above.
            finding["lifecycle"] = NEW
            finding["first_seen"] = (
                historical_finding.get("first_seen")
                or current_time
            )
            finding["times_seen"] = (
                historical_finding.get("times_seen", 1) + 1
            )
            finding["status"] = OPEN
            finding["last_seen"] = current_time
            new_count += 1

        else:
            finding["lifecycle"] = NEW
            finding["first_seen"] = (
                finding.get("first_seen")
                or current_time
            )
            finding["last_seen"] = current_time
            finding["times_seen"] = 1
            finding["status"] = OPEN
            new_count += 1

    # =====================================================
    # RESOLVED FINDINGS
    # =====================================================

    resolved_findings = []

    for fingerprint, previous_finding in previous.items():

        if fingerprint not in current:

            resolved = dict(previous_finding)

            resolved["status"] = RESOLVED
            resolved["lifecycle"] = LIFECYCLE_RESOLVED
            resolved["last_seen"] = current_time

            resolved_findings.append(resolved)
            resolved_count += 1

    # =====================================================
    # RETURN LIFECYCLE ANALYSIS
    # =====================================================

    return {
        "current_findings": list(current.values()),
        "resolved_findings": resolved_findings,
        "summary": {
            "new": new_count,
            "persistent": persistent_count,
            "reappeared": reappeared_count,
            "resolved": resolved_count,
        },
    }
