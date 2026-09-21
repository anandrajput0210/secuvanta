import re
from pathlib import Path


# =========================================================
# CONTEXT LEVELS
# =========================================================

EXPOSURE_LEVELS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}


# =========================================================
# FILE CONTEXT
# =========================================================

PRODUCTION_KEYWORDS = {
    "production",
    "prod",
    "release",
    "live",
}

HIGH_EXPOSURE_KEYWORDS = {
    "config",
    "configs",
    "settings",
    "secrets",
    "credentials",
    "deploy",
    "docker",
    "terraform",
    "kubernetes",
    "k8s",
    "helm",
}

LOW_EXPOSURE_KEYWORDS = {
    "test",
    "tests",
    "testing",
    "example",
    "examples",
    "demo",
    "sample",
    "mock",
    "mocks",
    "fixture",
    "fixtures",
}


# =========================================================
# CREDENTIAL CONTEXT
# =========================================================

CREDENTIAL_KEYWORDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "client_secret",
    "private_key",
    "access_key",
}


def _contains_keyword(path_parts, keywords):
    """
    Check whether any normalized path component
    contains one of the supplied keywords.
    """

    for part in path_parts:

        normalized = part.lower()

        for keyword in keywords:

            if keyword in normalized:
                return True

    return False


def _extract_variable_name(line):
    """
    Extract a likely variable name from an assignment.
    """

    match = re.search(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=",
        line,
    )

    if not match:
        return None

    return match.group(1).lower()


def _credential_name_signal(variable_name):
    """
    Determine whether the variable name suggests
    credential material.
    """

    if not variable_name:
        return False

    return any(
        keyword in variable_name
        for keyword in CREDENTIAL_KEYWORDS
    )


def analyze_context(
    file_path: str,
    line: str,
    finding_type: str,
):
    """
    Analyze contextual exposure around a finding.

    IMPORTANT:
    This function returns only metadata and reasons.
    It must never return or store the raw secret.
    """

    path = Path(file_path)

    path_parts = [
        part.lower()
        for part in path.parts
    ]

    reasons = []

    # =====================================================
    # FILE CONTEXT
    # =====================================================

    if _contains_keyword(
        path_parts,
        PRODUCTION_KEYWORDS,
    ):

        exposure = "CRITICAL"

        reasons.append(
            "Production/live context detected."
        )

    elif _contains_keyword(
        path_parts,
        HIGH_EXPOSURE_KEYWORDS,
    ):

        exposure = "HIGH"

        reasons.append(
            "Configuration or deployment context detected."
        )

    elif _contains_keyword(
        path_parts,
        LOW_EXPOSURE_KEYWORDS,
    ):

        exposure = "LOW"

        reasons.append(
            "Test/example/demo context detected."
        )

    else:

        exposure = "MEDIUM"

        reasons.append(
            "No strong environmental context detected."
        )

    # =====================================================
    # CODE CONTEXT
    # =====================================================

    variable_name = _extract_variable_name(line)

    if _credential_name_signal(variable_name):

        reasons.append(
            f"Credential-like variable name: {variable_name}."
        )

    # =====================================================
    # DETECTOR CONTEXT
    # =====================================================

    normalized_type = finding_type.lower()

    if "aws" in normalized_type:

        reasons.append(
            "Provider-specific AWS credential pattern detected."
        )

    elif "github" in normalized_type:

        reasons.append(
            "Provider-specific GitHub credential pattern detected."
        )

    elif "private key" in normalized_type:

        reasons.append(
            "Private cryptographic key marker detected."
        )

    elif "database" in normalized_type:

        reasons.append(
            "Database connection credential detected."
        )

    elif "jwt" in normalized_type:

        reasons.append(
            "Structured JWT token pattern detected."
        )

    # =====================================================
    # CONTEXT SCORE
    # =====================================================

    exposure_score = EXPOSURE_LEVELS[
        exposure
    ]

    return {
        "exposure": exposure,
        "exposure_score": exposure_score,
        "variable_name": variable_name,
        "reasons": reasons,
    }