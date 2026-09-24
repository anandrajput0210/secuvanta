import re

from core.models import Finding
from core.entropy import calculate_entropy, is_high_entropy
from core.fingerprint import generate_fingerprint
from core.context_engine import analyze_context

# =========================================================
# PATTERN-BASED DETECTION RULES
# =========================================================

DETECTION_RULES = [

    {
        "name": "AWS Access Key",
        "severity": "CRITICAL",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "description": "Possible AWS access key detected."
    },

    {
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "pattern": r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b",
        "description": "Possible GitHub authentication token detected."
    },

    {
        "name": "JWT Token",
        "severity": "HIGH",
        "pattern": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "description": "Possible JSON Web Token detected."
    },

    {
        "name": "Private Key",
        "severity": "CRITICAL",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "description": "Private cryptographic key detected."
    },

    {
        "name": "Database Connection String",
        "severity": "HIGH",
        "pattern": r"\b(?:postgres|postgresql|mysql|mongodb)://[^\s\"']+",
        "description": "Database connection string detected."
    },

    {
        "name": "Bearer Token",
        "severity": "HIGH",
        "pattern": r"\bBearer\s+[A-Za-z0-9._~+/=-]+\b",
        "description": "Possible bearer authentication token detected."
    },

]


# =========================================================
# PASSWORD DETECTION
# =========================================================

PASSWORD_PATTERN = re.compile(
    r"""(?ix)
    [A-Za-z0-9_]*
    (?:password|passwd|pwd|secret)
    [A-Za-z0-9_]*
    \s*
    [:=]
    \s*
    ["']?
    ([^\s"']{6,})
    """
)


# =========================================================
# CREDENTIAL ASSIGNMENT DETECTION
# =========================================================

CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b
    ([A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*
    ["']
    ([A-Za-z0-9_\-+/=]{20,})
    ["']
    """
)


CREDENTIAL_KEYWORDS = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "secret_key",
    "client_secret",
    "private_token",
}


# =========================================================
# SECRET MASKING
# =========================================================

def mask_secret(value: str) -> str:
    """
    Mask sensitive values so the full secret
    is never displayed or stored.
    """

    if len(value) <= 8:
        return "*" * len(value)

    visible_start = 4
    visible_end = 4

    return (
        value[:visible_start]
        + "*" * (len(value) - visible_start - visible_end)
        + value[-visible_end:]
    )

# =========================================================
# FINDING CREATION
# =========================================================

def create_finding(
    finding_type: str,
    severity: str,
    file_path: str,
    line_number: int,
    secret: str,
    description: str,
    entropy: float | None = None,
    source_line: str = "",
    fingerprint_file_path: str | None = None,
):
    """
    Create a Finding with fingerprint and contextual analysis.

    The raw secret is used only in memory to generate
    the fingerprint.

    The stored Finding receives only the masked value.

    fingerprint_file_path:
        Optional stable logical path used only for
        finding identity. When omitted, the real
        file_path is used exactly as before.
    """

    identity_path = (
        fingerprint_file_path
        if fingerprint_file_path is not None
        else file_path
    )

    fingerprint = generate_fingerprint(
        finding_type=finding_type,
        file_path=identity_path,
        secret_value=secret,
    )

    context = analyze_context(
        file_path=file_path,
        line=source_line,
        finding_type=finding_type,
    )

    return Finding(
        finding_type=finding_type,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        value=mask_secret(secret),
        description=description,
        entropy=entropy,
        fingerprint=fingerprint,

        exposure=context["exposure"],
        exposure_score=context["exposure_score"],
        context_reasons=context["reasons"],
        variable_name=context["variable_name"],
    )
    """
    Create a Finding safely.

    The raw secret is used only in memory to generate
    the fingerprint.

    The stored Finding receives ONLY the masked secret.
    """

    fingerprint = generate_fingerprint(
        finding_type=finding_type,
        file_path=file_path,
        secret_value=secret,
    )

    return Finding(
        finding_type=finding_type,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        value=mask_secret(secret),
        description=description,
        entropy=entropy,
        fingerprint=fingerprint,
    )


# =========================================================
# SECRET DETECTION
# =========================================================

def detect_secrets(
    text: str,
    file_path: str,
    fingerprint_file_path: str | None = None,
):
    """
    Scan text and return security findings.
    """

    findings = []

    lines = text.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # =================================================
        # PATTERN-BASED DETECTIONS
        # =================================================

        for rule in DETECTION_RULES:

            matches = re.finditer(
                rule["pattern"],
                line
            )

            for match in matches:

                secret = match.group()

                finding = create_finding(
                    finding_type=rule["name"],
                    severity=rule["severity"],
                    file_path=file_path,
                    line_number=line_number,
                    secret=secret,
                    description=rule["description"],
                    source_line=line,
                    fingerprint_file_path=fingerprint_file_path,
                )
                findings.append(finding)

        # =================================================
        # HIGH-ENTROPY CREDENTIAL DETECTION
        # =================================================

        credential_match = (
            CREDENTIAL_ASSIGNMENT_PATTERN.search(line)
        )

        if credential_match:

            variable_name = (
                credential_match.group(1).lower()
            )

            value = credential_match.group(2)

            is_credential_like = any(
                keyword in variable_name
                for keyword in CREDENTIAL_KEYWORDS
            )

            if (
                is_credential_like
                and is_high_entropy(value)
            ):

                # Avoid duplicate finding when a known
                # detector already found the same value.
                already_detected = any(
                    finding.file_path == file_path
                    and finding.line_number == line_number
                    and finding.value == mask_secret(value)
                    for finding in findings
                )

                if not already_detected:

                    entropy = calculate_entropy(value)

                    findings.append(
                        create_finding(
                            finding_type="High-Entropy Secret",
                            severity="MEDIUM",
                            file_path=file_path,
                            line_number=line_number,
                            secret=value,
                            description=(
                                "Suspicious credential-like value "
                                f"with Shannon entropy {entropy}."
                            ),
                            entropy=entropy,
                            source_line=line,
                            fingerprint_file_path=fingerprint_file_path,
                        )
                    )

        # =================================================
        # PASSWORD DETECTION
        # =================================================

        password_match = (
            PASSWORD_PATTERN.search(line)
        )

        if password_match:

            secret = password_match.group(1)

            findings.append(
                create_finding(
                    finding_type="Hardcoded Password",
                    severity="HIGH",
                    file_path=file_path,
                    line_number=line_number,
                    secret=secret,
                    description=(
                        "Possible hardcoded password detected."
                    ),
                    source_line=line,
                    fingerprint_file_path=fingerprint_file_path,
                )
            )

    return findings
# =========================================================
# EPHEMERAL SECRET RECOVERY
# =========================================================

def recover_secret_for_fingerprint(
    text: str,
    file_path: str,
    target_fingerprint: str,
):
    """
    Recover the exact raw secret corresponding to a finding
    fingerprint.

    The secret exists only in memory during this operation.
    It is never returned as part of a Finding object.

    Returns:
        raw secret string, or None
    """

    lines = text.splitlines()

    for line in lines:

        # -------------------------------------------------
        # Known pattern detections
        # -------------------------------------------------

        for rule in DETECTION_RULES:

            matches = re.finditer(
                rule["pattern"],
                line,
            )

            for match in matches:

                secret = match.group()

                fingerprint = generate_fingerprint(
                    finding_type=rule["name"],
                    file_path=file_path,
                    secret_value=secret,
                )

                if fingerprint == target_fingerprint:

                    return secret


        # -------------------------------------------------
        # Credential assignment detection
        # -------------------------------------------------

        credential_match = (
            CREDENTIAL_ASSIGNMENT_PATTERN.search(
                line
            )
        )

        if credential_match:

            variable_name = (
                credential_match.group(1).lower()
            )

            value = credential_match.group(2)

            is_credential_like = any(
                keyword in variable_name
                for keyword in CREDENTIAL_KEYWORDS
            )

            if (
                is_credential_like
                and is_high_entropy(value)
            ):

                fingerprint = generate_fingerprint(
                    finding_type="High-Entropy Secret",
                    file_path=file_path,
                    secret_value=value,
                )

                if fingerprint == target_fingerprint:

                    return value


        # -------------------------------------------------
        # Password detection
        # -------------------------------------------------

        password_match = (
            PASSWORD_PATTERN.search(
                line
            )
        )

        if password_match:

            secret = (
                password_match.group(1)
            )

            fingerprint = generate_fingerprint(
                finding_type="Hardcoded Password",
                file_path=file_path,
                secret_value=secret,
            )

            if fingerprint == target_fingerprint:

                return secret


    # -----------------------------------------------------
    # Fail closed
    # -----------------------------------------------------

    return None