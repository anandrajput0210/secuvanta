# =========================================================
# SECUVANTA RISK ENGINE
# Context-Aware and Explainable Security Risk Analysis
# =========================================================

from core.models import Finding


# =========================================================
# BASE SEVERITY SCORES
# =========================================================
#
# These represent the maximum contribution of a finding
# before confidence and exposure are considered.
#

SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 20,
}


# =========================================================
# CONFIDENCE MULTIPLIERS
# =========================================================

CONFIDENCE_MULTIPLIERS = {
    "VERY_HIGH": 1.00,
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.40,
}


# =========================================================
# EXPOSURE MULTIPLIERS
# =========================================================

EXPOSURE_MULTIPLIERS = {
    "CRITICAL": 1.00,
    "HIGH": 0.85,
    "MEDIUM": 0.65,
    "LOW": 0.40,
}


# =========================================================
# FALSE POSITIVE MULTIPLIERS
# =========================================================
#
# Lower false-positive risk means the finding should retain
# more of its calculated risk.
#

FALSE_POSITIVE_MULTIPLIERS = {
    "LOW": 1.00,
    "MEDIUM": 0.85,
    "HIGH": 0.55,
}


# =========================================================
# DETERMINE CONFIDENCE
# =========================================================

def calculate_confidence(finding: Finding) -> str:
    """
    Calculate confidence from multiple independent signals.

    Signals:
        1. Detector strength
        2. Credential-like variable name
        3. Entropy evidence
        4. Context evidence
    """

    finding_type = finding.finding_type.lower()

    score = 0

    # =====================================================
    # DETECTOR EVIDENCE
    # =====================================================

    if "aws access key" in finding_type:
        score += 60

    elif "github personal access token" in finding_type:
        score += 60

    elif "private key" in finding_type:
        score += 60

    elif "database connection" in finding_type:
        score += 50

    elif "jwt token" in finding_type:
        score += 45

    elif "bearer token" in finding_type:
        score += 45

    elif "hardcoded password" in finding_type:
        score += 30

    elif "entropy" in finding_type:
        score += 20

    else:
        score += 20

    # =====================================================
    # VARIABLE NAME EVIDENCE
    # =====================================================

    if finding.variable_name:

        credential_terms = (
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "access_token",
            "auth_token",
            "client_secret",
            "private_key",
        )

        variable_name = (
            finding.variable_name.lower()
        )

        if any(
            term in variable_name
            for term in credential_terms
        ):
            score += 20

    # =====================================================
    # ENTROPY EVIDENCE
    # =====================================================

    if finding.entropy is not None:

        if finding.entropy >= 4.5:
            score += 15

        elif finding.entropy >= 4.0:
            score += 10

    # =====================================================
    # CONTEXT EVIDENCE
    # =====================================================

    context_reasons = (
        getattr(
            finding,
            "context_reasons",
            None,
        )
        or []
    )

    if context_reasons:
        score += 5

    # =====================================================
    # FINAL CONFIDENCE
    # =====================================================

    if score >= 80:
        return "VERY_HIGH"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# =========================================================
# DETERMINE EXPOSURE
# =========================================================

def calculate_exposure(finding: Finding) -> str:
    """
    Use the contextual exposure already attached to the
    finding by the context engine.

    Falls back to MEDIUM when no contextual information
    is available.
    """

    exposure = getattr(
        finding,
        "exposure",
        None,
    )

    if exposure in EXPOSURE_MULTIPLIERS:
        return exposure

    return "MEDIUM"


# =========================================================
# DETERMINE FALSE POSITIVE RISK
# =========================================================

def calculate_false_positive_risk(
    finding: Finding,
) -> str:
    """
    Estimate the likelihood that a finding is a false positive.

    Multiple independent signals are considered:
        - Detector strength
        - Variable-name evidence
        - Entropy evidence
        - Context evidence
    """

    finding_type = finding.finding_type.lower()

    confidence_points = 0

    # =====================================================
    # DETECTOR STRENGTH
    # =====================================================

    if "aws access key" in finding_type:
        confidence_points += 60

    elif "github personal access token" in finding_type:
        confidence_points += 60

    elif "private key" in finding_type:
        confidence_points += 60

    elif "database connection" in finding_type:
        confidence_points += 50

    elif "jwt token" in finding_type:
        confidence_points += 45

    elif "bearer token" in finding_type:
        confidence_points += 45

    elif "hardcoded password" in finding_type:
        confidence_points += 30

    elif "entropy" in finding_type:
        confidence_points += 15

    else:
        confidence_points += 15

    # =====================================================
    # VARIABLE-NAME EVIDENCE
    # =====================================================

    if finding.variable_name:

        credential_terms = (
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "access_token",
            "auth_token",
            "client_secret",
            "private_key",
        )

        variable_name = (
            finding.variable_name.lower()
        )

        if any(
            term in variable_name
            for term in credential_terms
        ):
            confidence_points += 20

    # =====================================================
    # ENTROPY EVIDENCE
    # =====================================================

    if finding.entropy is not None:

        if finding.entropy >= 4.5:
            confidence_points += 15

        elif finding.entropy >= 4.0:
            confidence_points += 10

    # =====================================================
    # CONTEXT EVIDENCE
    # =====================================================

    context_reasons = (
        getattr(
            finding,
            "context_reasons",
            None,
        )
        or []
    )

    if context_reasons:
        confidence_points += 5

    # =====================================================
    # CLASSIFY FALSE-POSITIVE RISK
    # =====================================================

    if confidence_points >= 75:
        return "LOW"

    if confidence_points >= 45:
        return "MEDIUM"

    return "HIGH"


# =========================================================
# BUILD EXPLANATION
# =========================================================

def build_risk_reasons(
    finding: Finding,
    confidence: str,
    exposure: str,
    false_positive_risk: str,
):
    """
    Build human-readable evidence explaining the risk.
    """

    reasons = []

    # Detection evidence
    finding_type = finding.finding_type.lower()

    if "aws access key" in finding_type:
        reasons.append(
            "Provider-specific AWS credential signature detected."
        )

    elif "github personal access token" in finding_type:
        reasons.append(
            "Provider-specific GitHub token signature detected."
        )

    elif "private key" in finding_type:
        reasons.append(
            "Private cryptographic key marker detected."
        )

    elif "database connection" in finding_type:
        reasons.append(
            "Database credential connection string detected."
        )

    elif "jwt" in finding_type:
        reasons.append(
            "Structured JWT pattern detected."
        )

    elif "bearer token" in finding_type:
        reasons.append(
            "Bearer authentication token pattern detected."
        )

    elif "entropy" in finding_type:
        reasons.append(
            "High-entropy credential-like value detected."
        )

    # Variable-name evidence
    if finding.variable_name:
        reasons.append(
            f"Credential-like variable: "
            f"{finding.variable_name}."
        )

    # Context evidence
    context_reasons = (
        getattr(
            finding,
            "context_reasons",
            None,
        )
        or []
    )

    for reason in context_reasons:

        if reason not in reasons:
            reasons.append(reason)

    # Confidence evidence
    reasons.append(
        f"Detection confidence: {confidence}."
    )

    # False-positive evidence
    reasons.append(
        f"False-positive risk: {false_positive_risk}."
    )

    # Exposure conclusion
    reasons.append(
        f"Environmental exposure: {exposure}."
    )

    return reasons


# =========================================================
# CALCULATE INDIVIDUAL FINDING RISK
# =========================================================

def calculate_finding_risk(
    finding: Finding,
):
    """
    Calculate explainable risk for a single finding.

    Formula:

        severity
        × confidence
        × exposure
        × false-positive adjustment
    """

    severity = finding.severity.upper()

    base_score = SEVERITY_SCORES.get(
        severity,
        SEVERITY_SCORES["LOW"],
    )

    # -----------------------------------------
    # CONFIDENCE
    # -----------------------------------------

    confidence = calculate_confidence(
        finding
    )

    confidence_multiplier = (
        CONFIDENCE_MULTIPLIERS.get(
            confidence,
            0.65,
        )
    )

    # -----------------------------------------
    # EXPOSURE
    # -----------------------------------------

    exposure = calculate_exposure(
        finding
    )

    exposure_multiplier = (
        EXPOSURE_MULTIPLIERS.get(
            exposure,
            0.65,
        )
    )

    # -----------------------------------------
    # FALSE POSITIVE
    # -----------------------------------------

    false_positive_risk = (
        calculate_false_positive_risk(
            finding
        )
    )

    false_positive_multiplier = (
        FALSE_POSITIVE_MULTIPLIERS.get(
            false_positive_risk,
            0.85,
        )
    )

    # -----------------------------------------
    # FINAL RISK
    # -----------------------------------------

    risk_score = (
        base_score
        * confidence_multiplier
        * exposure_multiplier
        * false_positive_multiplier
    )

    risk_score = round(
        risk_score,
        2,
    )

    # -----------------------------------------
    # EXPLAINABILITY
    # -----------------------------------------

    reasons = build_risk_reasons(
        finding=finding,
        confidence=confidence,
        exposure=exposure,
        false_positive_risk=false_positive_risk,
    )

    return {

        "risk_score":
            risk_score,

        "confidence":
            confidence,

        "confidence_score":
            round(
                confidence_multiplier * 100
            ),

        "exposure":
            exposure,

        "exposure_score":
            getattr(
                finding,
                "exposure_score",
                50,
            ),

        "false_positive_risk":
            false_positive_risk,

        "risk_reasons":
            reasons,
    }


# =========================================================
# CALCULATE PROJECT RISK
# =========================================================

def calculate_project_risk(findings):
    """
    Calculate total project security risk.
    """

    total_score = 0

    analyzed_findings = []

    for finding in findings:

        intelligence = (
            calculate_finding_risk(
                finding
            )
        )

        total_score += (
            intelligence["risk_score"]
        )

        analyzed_findings.append({

            "finding": finding,

            "intelligence": intelligence,
        })

    # -----------------------------------------
    # PROJECT SCORE
    # -----------------------------------------

    final_score = min(
        round(total_score),
        100,
    )

    return {

        "risk_score":
            final_score,

        "risk_level":
            get_risk_level(
                final_score
            ),

        "findings":
            analyzed_findings,
    }


# =========================================================
# DETERMINE RISK LEVEL
# =========================================================

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "SAFE"