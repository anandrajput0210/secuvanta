import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from core.models import Finding
from core.fingerprint import generate_fingerprint

# =========================================================
# SUPPORTED DEPENDENCY MANIFESTS
# =========================================================

SUPPORTED_MANIFESTS = {
    "requirements.txt",
    "package-lock.json",
}

MAX_DEPENDENCY_MANIFEST_SIZE = 5 * 1024 * 1024
# =========================================================
# IGNORED DIRECTORIES
# =========================================================

IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".sentinelzero_backups",
}

# =========================================================
# REQUIREMENTS.TXT
# =========================================================

REQUIREMENT_LINE_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)"
    r"(?:\s*\[[^\]]+\])?"
    r"\s*(.*)$"
)


def parse_requirements(
    file_path: Path,
):
    """
    Extract dependencies from requirements.txt.

    Exact versions:
        requests==2.31.0
        flask===3.0.0

    Version ranges:
        requests>=2.31,<3
        flask~=3.0

    Unversioned:
        requests

    Exact versions are marked as resolved.
    Ranged/unversioned dependencies are marked unresolved
    so they can be handled separately by vulnerability lookup.
    """

    dependencies = []
    try:
        if file_path.stat().st_size > MAX_DEPENDENCY_MANIFEST_SIZE:
            return dependencies
    except OSError:
        return dependencies
    try:
        lines = file_path.read_text(
            encoding="utf-8"
        ).splitlines()

    except (OSError, UnicodeDecodeError):
        return dependencies

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        stripped = line.strip()

        # -------------------------------------------------
        # Ignore comments and empty lines
        # -------------------------------------------------

        if not stripped or stripped.startswith("#"):
            continue

        # -------------------------------------------------
        # Ignore pip options / flags
        # -------------------------------------------------

        if stripped.startswith("-"):
            continue

        # -------------------------------------------------
        # Remove inline comments
        # -------------------------------------------------

        dependency_line = stripped.split(
            "#",
            1
        )[0].strip()

        # -------------------------------------------------
        # Remove environment markers
        #
        # Example:
        # requests==2.31.0; python_version >= "3.9"
        # -------------------------------------------------

        dependency_line = dependency_line.split(
            ";",
            1
        )[0].strip()

        if not dependency_line:
            continue

        match = REQUIREMENT_LINE_PATTERN.match(
            dependency_line
        )

        if not match:
            continue

        package_name = match.group(1).strip()
        version_specifier = match.group(2).strip()

        version = None
        resolution_status = "unresolved"

        # -------------------------------------------------
        # Exact version detection
        #
        # Supported:
        #     ==2.31.0
        #     ===2.31.0
        # -------------------------------------------------

        exact_match = re.fullmatch(
            r"(?:===|==)\s*"
            r"([A-Za-z0-9_.!+~-]+)",
            version_specifier,
        )

        if exact_match:
            version = exact_match.group(1)
            resolution_status = "exact"

        dependencies.append(
            {
                "name": package_name,
                "version": version,
                "version_specifier": (
                    version_specifier
                    if version_specifier
                    else None
                ),
                "resolution_status": resolution_status,
                "ecosystem": "PyPI",
                "manifest": str(file_path),
                "line_number": line_number,
            }
        )

    return dependencies

# =========================================================
# SINGLE MANIFEST DISPATCH
# =========================================================


def parse_manifest(
    file_path: Path,
    metadata: dict | None = None,
):
    """Parse one supported dependency manifest."""

    filename = file_path.name.lower()

    if filename == "requirements.txt":
        return parse_requirements(file_path)

    if filename == "package-lock.json":
        return parse_package_lock(
            file_path,
            metadata=metadata,
        )

    return []


# =========================================================
# PACKAGE-LOCK.JSON
# =========================================================


def parse_package_lock(
    file_path: Path,
    metadata: dict | None = None,
):
    """Extract locked npm package versions from package-lock.json."""

    dependencies = []

    def mark_incomplete(reason: str) -> None:
        if metadata is not None:
            metadata.setdefault("incomplete_reasons", [])
            metadata.setdefault("skipped_manifests", 0)
            metadata["skipped_manifests"] += 1
            metadata["incomplete_reasons"].append(
                f"{reason}: {file_path.name}"
            )

    try:
        if file_path.stat().st_size > MAX_DEPENDENCY_MANIFEST_SIZE:
            mark_incomplete("Manifest exceeds 5 MiB limit")
            return dependencies
    except OSError:
        mark_incomplete("Could not inspect manifest")
        return dependencies

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        mark_incomplete("Could not read or parse manifest")
        return dependencies

    if not isinstance(data, dict):
        mark_incomplete("Invalid manifest structure")
        return dependencies

    packages = data.get("packages", {})

    if not isinstance(packages, dict):
        mark_incomplete("Invalid packages structure")
        return dependencies

    for package_path, package_info in packages.items():
        if not isinstance(package_path, str):
            continue

        if not package_path.startswith("node_modules/"):
            continue

        if not isinstance(package_info, dict):
            continue

        version = package_info.get("version")
        if not version:
            continue

        package_name = package_path[len("node_modules/"):]

        dependencies.append({
            "name": package_name,
            "version": str(version),
            "version_specifier": f"=={version}",
            "resolution_status": "exact",
            "ecosystem": "npm",
            "manifest": str(file_path),
            "line_number": 0,
        })

    return dependencies

# =========================================================
# DEPENDENCY DISCOVERY
# =========================================================

def discover_dependencies(
    project_root: str,
    metadata: dict | None = None,
):

    """
    Recursively discover supported dependency manifests.

    Returns a normalized list of dependencies.
    """

    root = Path(project_root)

    if not root.exists():
        raise FileNotFoundError(
            f"Project directory not found: {project_root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Not a project directory: {project_root}"
        )

    dependencies = []

    if metadata is not None:
        metadata.setdefault("incomplete_reasons", [])
        metadata.setdefault("skipped_manifests", 0)

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if any(
            part.lower()
            in IGNORED_DIRECTORIES
            for part in file_path.parts
        ):
            continue

        if (
            file_path.name.lower()
            not in SUPPORTED_MANIFESTS
        ):
            continue
        try:
            manifest_size = file_path.stat().st_size
        except OSError:
            if metadata is not None:
                metadata["skipped_manifests"] += 1
                metadata["incomplete_reasons"].append(
                    f"Could not inspect manifest: {file_path.name}"
                )
            continue

        if manifest_size > MAX_DEPENDENCY_MANIFEST_SIZE:
            if metadata is not None:
                metadata["skipped_manifests"] += 1
                metadata["incomplete_reasons"].append(
                    f"Manifest exceeds 5 MiB limit: {file_path.name}"
                )
            continue
        dependencies.extend(
            parse_manifest(
                file_path
            )
        )

    # -----------------------------------------------------
    # DEDUPLICATE
    # -----------------------------------------------------

    unique = {}

    for dependency in dependencies:

        key = (
            dependency["ecosystem"].lower(),
            dependency["name"].lower(),
            dependency["version"],
        )

        unique[key] = dependency

    return list(
        unique.values()
    )


# =========================================================
# SUMMARY
# =========================================================

def summarize_dependencies(
    dependencies,
):
    """
    Create a small summary for APIs/UI later.
    """

    ecosystems = {}

    for dependency in dependencies:

        ecosystem = dependency[
            "ecosystem"
        ]

        ecosystems[ecosystem] = (
            ecosystems.get(
                ecosystem,
                0,
            )
            + 1
        )

    return {
        "total_dependencies": len(
            dependencies
        ),
        "ecosystems": ecosystems,
    }

# =========================================================
# OSV VULNERABILITY LOOKUP
# =========================================================

OSV_QUERY_URL = "https://api.osv.dev/v1/query"



def query_osv_vulnerabilities(dependency):
    """Query OSV for vulnerabilities affecting an exact version."""
    if not dependency.get("version"):
        return {
            "status": "VERSION_UNRESOLVED",
            "dependency": dependency,
            "vulnerabilities": [],
            "error": (
                "Exact dependency version is required "
                "for vulnerability lookup."
            ),
        }

    payload = {
        "package": {
            "name": dependency["name"],
            "ecosystem": dependency["ecosystem"],
        },
        "version": dependency["version"],
    }

    max_response_bytes = 5 * 1024 * 1024

    try:
        request_data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            OSV_QUERY_URL,
            data=request_data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            response_body = response.read(max_response_bytes + 1)

        if len(response_body) > max_response_bytes:
            raise ValueError(
                "OSV response exceeded the 5 MiB size limit."
            )

        data = json.loads(response_body.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("OSV response must be a JSON object.")

        vulnerabilities = data.get("vulns", [])

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "OSV response field 'vulns' must be a list."
            )

        if not all(isinstance(item, dict) for item in vulnerabilities):
            raise ValueError(
                "OSV response contains an invalid vulnerability record."
            )

        return {
            "status": "SUCCESS",
            "dependency": dependency,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
        }

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        OSError,
    ) as exc:
        return {
            "status": "ERROR",
            "dependency": dependency,
            "vulnerabilities": [],
            "vulnerability_count": 0,
            "error": str(exc),
        }

# =========================================================
# NORMALIZE OSV VULNERABILITY
# =========================================================

def normalize_osv_vulnerability(
    vulnerability,
):
    """
    Convert an OSV vulnerability record into a compact,
    SecuVanta-friendly structure.

    Raw OSV response data is intentionally not modified.
    """

    if not isinstance(
        vulnerability,
        dict,
    ):
        return {
            "id": None,
            "aliases": [],
            "cve": None,
            "summary": "",
            "severity": "UNKNOWN",
            "cvss": [],
            "fixed_versions": [],
            "references": [],
        }

    vulnerability_id = vulnerability.get(
        "id"
    )

    aliases = [
        str(alias)
        for alias in vulnerability.get(
            "aliases",
            []
        )
        if alias
    ]

    cve = next(
        (
            alias
            for alias in aliases
            if alias.upper().startswith(
                "CVE-"
            )
        ),
        None,
    )

    # -----------------------------------------------------
    # SEVERITY
    # -----------------------------------------------------

    database_specific = (
        vulnerability.get(
            "database_specific"
        )
        or {}
    )

    severity = database_specific.get(
        "severity"
    )

    # Some records place severity inside
    # affected package metadata.
    if not severity:

        for affected in vulnerability.get(
            "affected",
            []
        ):

            affected_database_specific = (
                affected.get(
                    "database_specific"
                )
                or {}
            )

            severity = (
                affected_database_specific.get(
                    "severity"
                )
            )

            if severity:
                break

    if not severity:
        severity = "UNKNOWN"

    # -----------------------------------------------------
    # CVSS
    # -----------------------------------------------------

    cvss = []

    for item in vulnerability.get(
        "severity",
        []
    ):

        if not isinstance(
            item,
            dict,
        ):
            continue

        score = item.get(
            "score"
        )

        if score:
            cvss.append(
                {
                    "type": item.get(
                        "type"
                    ),
                    "score": score,
                }
            )

    # -----------------------------------------------------
    # FIXED VERSIONS
    # -----------------------------------------------------

    fixed_versions = []

    for affected in vulnerability.get(
        "affected",
        []
    ):

        for version_range in affected.get(
            "ranges",
            []
        ):

            for event in version_range.get(
                "events",
                []
            ):

                fixed = event.get(
                    "fixed"
                )

                if fixed:
                    fixed_versions.append(
                        str(fixed)
                    )

    fixed_versions = sorted(
        set(fixed_versions)
    )

    # -----------------------------------------------------
    # REFERENCES
    # -----------------------------------------------------

    references = []

    for reference in vulnerability.get(
        "references",
        []
    ):

        if not isinstance(
            reference,
            dict,
        ):
            continue

        url = reference.get(
            "url"
        )

        if url:
            references.append(
                {
                    "type": reference.get(
                        "type"
                    ),
                    "url": url,
                }
            )

    return {
        "id": vulnerability_id,
        "aliases": aliases,
        "cve": cve,
        "summary": vulnerability.get(
            "summary",
            ""
        ),
        "severity": str(
            severity
        ).upper(),
        "cvss": cvss,
        "fixed_versions": fixed_versions,
        "references": references,
    }
# =========================================================
# DEPENDENCY VULNERABILITY SCAN
# =========================================================

def scan_dependencies(
    project_root: str,
    fingerprint_root: str | None = None,
):
    """
    Discover project dependencies and query OSV for
    dependencies with exact resolved versions.

    Unresolved dependencies are preserved and reported
    separately rather than silently ignored.
    """
    identity_root = Path(
        fingerprint_root
        if fingerprint_root is not None
        else project_root
    ).resolve()

    discovery_metadata = {
        "incomplete_reasons": [],
        "skipped_manifests": 0,
    }

    dependencies = discover_dependencies(
        project_root,
        metadata=discovery_metadata,
    )
    results = []

    findings = []
    for dependency in dependencies:

        # -------------------------------------------------
        # VERSION NOT RESOLVED
        # -------------------------------------------------

        if not dependency.get("version"):

            results.append(
                {
                    "status": "VERSION_UNRESOLVED",
                    "dependency": dependency,
                    "vulnerabilities": [],
                    "vulnerability_count": 0,
                    "error": (
                        "Exact dependency version could "
                        "not be determined."
                    ),
                }
            )

            continue

        # -------------------------------------------------
        # OSV LOOKUP
        # -------------------------------------------------

        lookup_result = (
            query_osv_vulnerabilities(
                dependency
            )
        )

        normalized_vulnerabilities = (
            deduplicate_vulnerabilities(
                lookup_result.get(
                    "vulnerabilities",
                    []
                )
            )
        )

        for vulnerability in normalized_vulnerabilities:


            manifest_path = Path(
                dependency["manifest"]
            )

            try:
                logical_manifest = (
                    manifest_path.resolve()
                    .relative_to(identity_root)
                    .as_posix()
                )

            except ValueError:
                logical_manifest = (
                    manifest_path.name
                )

            finding = (
                vulnerability_to_secuvanta_finding(
                    dependency,
                    vulnerability,
                    fingerprint_file_path=logical_manifest,
                )
            )
            findings.append(
                finding
            )

        results.append(
            {
                "status": lookup_result.get(
                    "status",
                    "ERROR",
                ),
                "dependency": dependency,
                "vulnerabilities":
                    normalized_vulnerabilities,
                "vulnerability_count":
                    len(normalized_vulnerabilities),
                "error":
                    lookup_result.get(
                        "error"
                    ),
            }
        )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    vulnerable_dependencies = 0
    total_vulnerabilities = 0
    unresolved_dependencies = 0
    lookup_errors = 0

    for result in results:

        count = result.get(
            "vulnerability_count",
            0,
        )

        total_vulnerabilities += count

        if count > 0:
            vulnerable_dependencies += 1

        if result.get("status") == (
            "VERSION_UNRESOLVED"
        ):
            unresolved_dependencies += 1

        if result.get("status") == "ERROR":
            lookup_errors += 1

    return {
        "dependencies": dependencies,
        "results": results,
        "findings": findings,
        "summary": {
            "total_dependencies":
                len(dependencies),

            "vulnerable_dependencies":
                vulnerable_dependencies,

            "total_vulnerabilities":
                total_vulnerabilities,

            "unresolved_dependencies":
                unresolved_dependencies,

            "lookup_errors":
                lookup_errors,

            "skipped_manifests": discovery_metadata[
                "skipped_manifests"
            ],
            "incomplete_reasons": discovery_metadata[
                "incomplete_reasons"
            ],
            "incomplete": bool(
                discovery_metadata["incomplete_reasons"]
            ),
        },
    }
# =========================================================
# DEDUPLICATE VULNERABILITIES
# =========================================================

def deduplicate_vulnerabilities(
    vulnerabilities,
):
    """
    Remove duplicate OSV records that represent the same
    underlying vulnerability through shared aliases.

    Example:
        GHSA-xxxxx -> CVE-2025-1234
        PYSEC-xxxx -> CVE-2025-1234

    These are treated as one vulnerability.
    """

    unique = {}

    for vulnerability in vulnerabilities:

        normalized = normalize_osv_vulnerability(
            vulnerability
        )

        identifiers = set(
            normalized.get(
                "aliases",
                []
            )
        )

        if normalized.get("id"):
            identifiers.add(
                normalized["id"]
            )

        # -------------------------------------------------
        # Find an existing vulnerability sharing any ID
        # -------------------------------------------------

        existing_key = None

        for key, existing in unique.items():

            existing_ids = set(
                existing.get(
                    "aliases",
                    []
                )
            )

            if existing.get("id"):
                existing_ids.add(
                    existing["id"]
                )

            if identifiers & existing_ids:
                existing_key = key
                break

        # -------------------------------------------------
        # New vulnerability
        # -------------------------------------------------

        if existing_key is None:

            key = (
                normalized.get("cve")
                or normalized.get("id")
            )

            unique[key] = normalized

            continue

        # -------------------------------------------------
        # Merge identifiers from duplicate records
        # -------------------------------------------------

        existing = unique[
            existing_key
        ]

        merged_aliases = sorted(
            set(
                existing.get(
                    "aliases",
                    []
                )
                + normalized.get(
                    "aliases",
                    []
                )
            )
        )

        existing["aliases"] = (
            merged_aliases
        )

        # Prefer an available CVE
        if (
            not existing.get("cve")
            and normalized.get("cve")
        ):
            existing["cve"] = (
                normalized["cve"]
            )

        # Merge fixed versions
        existing["fixed_versions"] = sorted(
            set(
                existing.get(
                    "fixed_versions",
                    []
                )
                + normalized.get(
                    "fixed_versions",
                    []
                )
            )
        )

        # Merge references
        existing_references = (
            existing.get(
                "references",
                []
            )
        )

        for reference in normalized.get(
            "references",
            []
        ):
            if reference not in existing_references:
                existing_references.append(
                    reference
                )

        existing["references"] = (
            existing_references
        )

    return list(
        unique.values()
    )

# =========================================================
# CONVERT VULNERABILITY TO SECUVANTA FINDING
# =========================================================

def vulnerability_to_finding(
    dependency,
    vulnerability,
):
    """
    Convert a normalized vulnerability into a SecuVanta-
    compatible finding structure.

    This does not modify the original dependency or
    vulnerability objects.
    """

    severity = str(
        vulnerability.get(
            "severity",
            "UNKNOWN",
        )
    ).upper()

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "UNKNOWN",
    }

    mapped_severity = severity_map.get(
        severity,
        "UNKNOWN",
    )

    vulnerability_id = (
        vulnerability.get("cve")
        or vulnerability.get("id")
    )

    fixed_versions = vulnerability.get(
        "fixed_versions",
        [],
    )

    remediation = (
        f"Upgrade {dependency['name']} "
        f"to a fixed version."
        if fixed_versions
        else
        f"Review {dependency['name']} "
        f"for a patched or supported release."
    )

    if fixed_versions:
        remediation += (
            " Recommended fixed version(s): "
            + ", ".join(fixed_versions)
            + "."
        )

    finding = {
        "type": "DEPENDENCY_VULNERABILITY",
        "title": (
            f"Vulnerable dependency: "
            f"{dependency['name']}"
        ),
        "severity": mapped_severity,
        "package": dependency["name"],
        "version": dependency.get(
            "version"
        ),
        "ecosystem": dependency.get(
            "ecosystem"
        ),
        "manifest": dependency.get(
            "manifest"
        ),
        "line_number": dependency.get(
            "line_number"
        ),
        "vulnerability_id": vulnerability_id,
        "osv_id": vulnerability.get(
            "id"
        ),
        "aliases": vulnerability.get(
            "aliases",
            [],
        ),
        "summary": vulnerability.get(
            "summary",
            "",
        ),
        "cvss": vulnerability.get(
            "cvss",
            [],
        ),
        "fixed_versions": fixed_versions,
        "references": vulnerability.get(
            "references",
            [],
        ),
        "remediation": remediation,
    }

    return finding

# =========================================================
# CREATE SECUVANTA FINDING OBJECT
# =========================================================

def vulnerability_to_secuvanta_finding(
    dependency,
    vulnerability,
    fingerprint_file_path=None,
):
    """
    Convert a normalized dependency vulnerability into
    SecuVanta's Finding dataclass.

    The fingerprint intentionally uses:
        finding type + manifest path + vulnerability ID

    The dependency version is NOT part of the fingerprint.
    This allows a vulnerable dependency to become RESOLVED
    after upgrading rather than appearing as a completely
    new finding.
    """

    severity = str(
        vulnerability.get(
            "severity",
            "UNKNOWN",
        )
    ).upper()

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }

    mapped_severity = severity_map.get(
        severity,
        "LOW",
    )

    vulnerability_id = (
        vulnerability.get("cve")
        or vulnerability.get("id")
        or "UNKNOWN-VULNERABILITY"
    )

    package_name = dependency.get(
        "name",
        "unknown",
    )

    version = dependency.get(
        "version"
    )

    manifest = dependency.get(
        "manifest",
        "",
    )

    line_number = dependency.get(
        "line_number",
        0,
    )

    fixed_versions = vulnerability.get(
        "fixed_versions",
        [],
    )

    summary = vulnerability.get(
        "summary",
        "",
    )

    remediation = (
        f"Upgrade {package_name} to a fixed version."
    )

    if fixed_versions:
        remediation += (
            " Recommended fixed version(s): "
            + ", ".join(fixed_versions)
            + "."
        )

    description_parts = [
        f"{vulnerability_id}: {summary}",
        f"Dependency: {package_name}",
    ]

    if version:
        description_parts.append(
            f"Version: {version}"
        )

    if fixed_versions:
        description_parts.append(
            "Fixed version(s): "
            + ", ".join(fixed_versions)
        )

    description_parts.append(
        f"Remediation: {remediation}"
    )

    description = " ".join(
        description_parts
    )

    identity_path = (
        fingerprint_file_path
        if fingerprint_file_path is not None
        else manifest
    )

    fingerprint = generate_fingerprint(
        finding_type="DEPENDENCY_VULNERABILITY",
        file_path=identity_path,
        secret_value=vulnerability_id,
    )

    return Finding(
        finding_type="DEPENDENCY_VULNERABILITY",
        severity=mapped_severity,
        file_path=manifest,
        line_number=line_number,
        value=(
            f"{package_name}"
            f"@{version or 'UNRESOLVED'}"
            f" [{vulnerability_id}]"
        ),
        description=description,
        fingerprint=fingerprint,
    )