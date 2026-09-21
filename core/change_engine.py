from typing import Any


def build_finding_map(findings):
    """
    Build fingerprint -> finding mapping.

    Fingerprint is the canonical finding identity.
    """

    return {
        finding.get("fingerprint"): finding
        for finding in findings
        if finding.get("fingerprint")
    }


def calculate_change(previous_scan, current_scan):
    """
    Compare two scans using backend finding fingerprints.

    Returns:
        - risk change
        - risk reduction
        - new findings
        - persistent findings
        - resolved findings
        - reappeared findings
        - security improvement state
    """

    if not previous_scan or not current_scan:
        return {
            "available": False,
            "risk_change": 0,
            "risk_reduction": 0,
            "new_findings": [],
            "persistent_findings": [],
            "resolved_findings": [],
            "reappeared_findings": [],
            "security_improved": False,
        }

    previous_findings = previous_scan.get(
        "findings",
        [],
    )

    current_findings = current_scan.get(
        "findings",
        [],
    )

    previous_map = build_finding_map(
        previous_findings
    )

    current_map = build_finding_map(
        current_findings
    )

    previous_risk = float(
        previous_scan.get(
            "risk_score",
            0,
        )
    )

    current_risk = float(
        current_scan.get(
            "risk_score",
            0,
        )
    )

    risk_change = round(
        current_risk - previous_risk,
        2,
    )

    risk_reduction = round(
        max(
            previous_risk - current_risk,
            0,
        ),
        2,
    )

    new_findings = []

    persistent_findings = []

    reappeared_findings = []

    resolved_findings = []


    # =====================================================
    # CURRENT FINDINGS
    # =====================================================

    for fingerprint, finding in current_map.items():

        previous_finding = previous_map.get(
            fingerprint
        )

        if previous_finding is None:

            lifecycle = (
                finding.get(
                    "lifecycle",
                    "NEW",
                )
            )

            if lifecycle == "REAPPEARED":

                reappeared_findings.append(
                    finding
                )

            else:

                new_findings.append(
                    finding
                )

        else:

            persistent_findings.append(
                finding
            )


    # =====================================================
    # RESOLVED FINDINGS
    # =====================================================

    for fingerprint, finding in previous_map.items():

        if fingerprint not in current_map:

            resolved_findings.append(
                finding
            )


    # =====================================================
    # IMPROVEMENT DECISION
    # =====================================================

    security_improved = (
        current_risk < previous_risk
        or len(resolved_findings) > 0
    )


    return {
        "available": True,

        "previous_risk":
            previous_risk,

        "current_risk":
            current_risk,

        "risk_change":
            risk_change,

        "risk_reduction":
            risk_reduction,

        "new_findings":
            new_findings,

        "persistent_findings":
            persistent_findings,

        "resolved_findings":
            resolved_findings,

        "reappeared_findings":
            reappeared_findings,

        "security_improved":
            security_improved,
    }