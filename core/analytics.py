# =========================================================
# SECUVANTA ANALYTICS ENGINE
# =========================================================


def calculate_analytics(history):

    """
    Calculate security analytics from scan history.
    History is expected to be ordered newest first.
    """

    # =====================================================
    # NO HISTORY
    # =====================================================

    if not history:

        return {

            "total_scans": 0,

            "average_risk": 0,

            "latest_risk": 0,

            "highest_risk": 0,

            "lowest_risk": 0,

            "risk_trend": "NO_DATA",

            "risk_change": 0,

            "total_findings": 0,

        }


    # =====================================================
    # BASIC DATA
    # =====================================================

    total_scans = len(history)


    risk_scores = [

        scan.get("risk_score", 0)

        for scan in history

    ]


    finding_counts = [

        scan.get("total_findings", 0)

        for scan in history

    ]


    # =====================================================
    # RISK STATISTICS
    # =====================================================

    latest_risk = history[0].get(
        "risk_score",
        0
    )


    average_risk = round(

        sum(risk_scores) / total_scans,

        1

    )


    highest_risk = max(risk_scores)


    lowest_risk = min(risk_scores)


    # =====================================================
    # FINDING STATISTICS
    # =====================================================

    total_findings = sum(
        finding_counts
    )


    # =====================================================
    # RISK TREND
    # =====================================================

    risk_change = 0

    risk_trend = "STABLE"


    if total_scans < 2:

        risk_trend = "NO_COMPARISON"


    else:

        previous_risk = history[1].get(
            "risk_score",
            0
        )


        risk_change = latest_risk - previous_risk


        if risk_change > 0:

            risk_trend = "INCREASED"


        elif risk_change < 0:

            risk_trend = "DECREASED"


        else:

            risk_trend = "STABLE"


    # =====================================================
    # RETURN ANALYTICS
    # =====================================================

    return {

        "total_scans": total_scans,

        "average_risk": average_risk,

        "latest_risk": latest_risk,

        "highest_risk": highest_risk,

        "lowest_risk": lowest_risk,

        "risk_trend": risk_trend,

        "risk_change": risk_change,

        "total_findings": total_findings,

    }


# =========================================================
# SECUVANTA SECURITY POSTURE ENGINE
# =========================================================


def calculate_security_posture(history):

    """
    Calculate the overall security posture of the project.

    History is expected to be ordered newest first.

    The posture score combines:

    - Current project risk
    - Risk movement
    - Resolved findings
    - New findings
    - Persistent findings
    - Reappeared findings

    Score range:
        0   = POOR
        50+ = NEEDS_ATTENTION
        80+ = GOOD
    """

    # =====================================================
    # NO HISTORY
    # =====================================================

    if not history:

        return {

            "posture_score": 0,

            "posture": "NO_DATA",

            "posture_trend": "NO_DATA",

            "risk_change": 0,

            "new_findings": 0,

            "persistent_findings": 0,

            "reappeared_findings": 0,

            "resolved_findings": 0,

            "explanation": "No scan history is available to determine security posture.",

        }


    # =====================================================
    # CURRENT SCAN
    # =====================================================

    current_scan = history[0]


    current_risk = current_scan.get(
        "risk_score",
        0
    )


    # =====================================================
    # PREVIOUS SCAN
    # =====================================================

    has_previous_scan = len(history) >= 2


    previous_risk = current_risk


    risk_change = 0


    if has_previous_scan:

        previous_risk = history[1].get(
            "risk_score",
            0
        )

        risk_change = current_risk - previous_risk


    # =====================================================
    # LIFECYCLE DATA
    # =====================================================

    lifecycle_summary = current_scan.get(
        "lifecycle_summary",
        {}
    )


    new_findings = lifecycle_summary.get(
        "new",
        0
    )


    persistent_findings = lifecycle_summary.get(
        "persistent",
        0
    )


    reappeared_findings = lifecycle_summary.get(
        "reappeared",
        0
    )


    resolved_findings = lifecycle_summary.get(
        "resolved",
        0
    )


    # =====================================================
    # BASE POSTURE
    # =====================================================

    # Lower risk means healthier posture.

    posture_score = 100 - current_risk


    # =====================================================
    # POSITIVE SIGNALS
    # =====================================================

    # Risk reduction is a strong positive signal.

    if risk_change < 0:

        posture_score += 5


    # Resolved findings improve project health.

    posture_score += resolved_findings * 2


    # A clean scan transition with no reappearances
    # is a small positive signal.

    if has_previous_scan and reappeared_findings == 0:

        posture_score += 3


    # =====================================================
    # NEGATIVE SIGNALS
    # =====================================================

    # Risk increase means the project is becoming weaker.

    if risk_change > 0:

        posture_score -= 5


    # Newly discovered findings reduce posture.

    posture_score -= new_findings * 3


    # Persistent findings indicate unresolved risk.

    posture_score -= persistent_findings * 1


    # Reappeared findings are more serious because
    # previously resolved problems have returned.

    posture_score -= reappeared_findings * 6


    # =====================================================
    # LIMIT SCORE
    # =====================================================

    posture_score = max(
        0,
        min(100, posture_score)
    )


    # =====================================================
    # POSTURE CLASSIFICATION
    # =====================================================

    if posture_score >= 80:

        posture = "GOOD"


    elif posture_score >= 50:

        posture = "NEEDS_ATTENTION"


    else:

        posture = "POOR"


    # =====================================================
    # POSTURE TREND
    # =====================================================

    if not has_previous_scan:

        posture_trend = "NO_COMPARISON"


    elif risk_change < 0:

        posture_trend = "IMPROVING"


    elif risk_change > 0:

        posture_trend = "WORSENING"


    else:

        posture_trend = "STABLE"


    # =====================================================
    # EXPLANATION
    # =====================================================

    explanation_parts = []


    if risk_change < 0:

        explanation_parts.append(
            f"Risk decreased from {previous_risk} to {current_risk}."
        )


    elif risk_change > 0:

        explanation_parts.append(
            f"Risk increased from {previous_risk} to {current_risk}."
        )


    else:

        explanation_parts.append(
            f"Risk remained at {current_risk}."
        )


    if resolved_findings > 0:

        explanation_parts.append(
            f"{resolved_findings} finding(s) were resolved."
        )


    if new_findings > 0:

        explanation_parts.append(
            f"{new_findings} new finding(s) appeared."
        )


    if persistent_findings > 0:

        explanation_parts.append(
            f"{persistent_findings} finding(s) remain persistent."
        )


    if reappeared_findings > 0:

        explanation_parts.append(
            f"{reappeared_findings} previously resolved finding(s) reappeared."
        )


    if (
        has_previous_scan
        and resolved_findings == 0
        and new_findings == 0
        and reappeared_findings == 0
    ):

        explanation_parts.append(
            "No new or reappeared findings were detected."
        )


    explanation = " ".join(
        explanation_parts
    )


    # =====================================================
    # RETURN SECURITY POSTURE
    # =====================================================

    return {

        "posture_score": posture_score,

        "posture": posture,

        "posture_trend": posture_trend,

        "risk_change": risk_change,

        "new_findings": new_findings,

        "persistent_findings": persistent_findings,

        "reappeared_findings": reappeared_findings,

        "resolved_findings": resolved_findings,

        "explanation": explanation,

    }