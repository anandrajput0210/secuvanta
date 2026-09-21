# =========================================================
# SECUVANTA PROTECTION POLICY
# Safe decision-making for live protection
# =========================================================


# =========================================================
# PROTECTION MODES
# =========================================================

MONITOR = "MONITOR"
GUARDED = "GUARDED"
AUTO_PROTECT = "AUTO_PROTECT"


VALID_MODES = {
    MONITOR,
    GUARDED,
    AUTO_PROTECT,
}


# =========================================================
# ACTIONS
# =========================================================

NO_ACTION = "NO_ACTION"
ALERT = "ALERT"
PROPOSE = "PROPOSE"
CONTAIN = "CONTAIN"


# =========================================================
# POLICY DECISION
# =========================================================

def decide_action(
    mode: str,
    severity: str,
    confidence: str,
    exposure: str,
    false_positive_risk: str,
):
    """
    Decide what SecuVanta is allowed to do.
    This function never modifies files.
    It only decides the permitted action.
    """

    mode = str(mode).upper()
    severity = str(severity).upper()
    confidence = str(confidence).upper()
    exposure = str(exposure).upper()
    false_positive_risk = (
        str(false_positive_risk).upper()
    )

    if mode not in VALID_MODES:
        raise ValueError(
            f"Unsupported protection mode: {mode}"
        )


    # =====================================================
    # MONITOR MODE
    # =====================================================

    if mode == MONITOR:

        if severity in {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        }:
            return {
                "action": ALERT,
                "automatic": False,
                "reason": (
                    "Monitor mode only reports the finding."
                ),
            }

        return {
            "action": NO_ACTION,
            "automatic": False,
            "reason": "No actionable finding.",
        }


    # =====================================================
    # GUARDED MODE
    # =====================================================

    if mode == GUARDED:

        if false_positive_risk == "HIGH":

            return {
                "action": ALERT,
                "automatic": False,
                "reason": (
                    "High false-positive risk requires "
                    "manual review."
                ),
            }


        if confidence in {
            "HIGH",
            "VERY_HIGH",
        }:

            return {
                "action": PROPOSE,
                "automatic": False,
                "reason": (
                    "High-confidence finding detected. "
                    "Safe remediation can be proposed."
                ),
            }


        return {
            "action": ALERT,
            "automatic": False,
            "reason": (
                "Finding requires manual verification."
            ),
        }


    # =====================================================
    # AUTO PROTECT MODE
    # =====================================================

    # Never automatically modify uncertain findings.
    if false_positive_risk == "HIGH":

        return {
            "action": ALERT,
            "automatic": False,
            "reason": (
                "Automatic protection blocked because "
                "false-positive risk is high."
            ),
        }


    # Only very-high confidence findings qualify.
    if confidence != "VERY_HIGH":

        return {
            "action": PROPOSE,
            "automatic": False,
            "reason": (
                "Confidence is insufficient for automatic "
                "containment."
            ),
        }


    # Critical/high production-style exposures qualify.
    if severity == "CRITICAL" and exposure in {
        "CRITICAL",
        "HIGH",
    }:

        return {
            "action": CONTAIN,
            "automatic": True,
            "reason": (
                "Very-high confidence critical exposure "
                "meets automatic containment policy."
            ),
        }


    if severity == "HIGH" and exposure == "CRITICAL":

        return {
            "action": CONTAIN,
            "automatic": True,
            "reason": (
                "Very-high confidence high-severity "
                "critical exposure meets policy."
            ),
        }


    # Everything else is proposed, not automatically changed.
    return {
        "action": PROPOSE,
        "automatic": False,
        "reason": (
            "Finding is significant but does not meet "
            "automatic containment requirements."
        ),
    }