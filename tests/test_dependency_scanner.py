import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.dependency_scanner import (
    deduplicate_vulnerabilities,
    discover_dependencies,
    normalize_osv_vulnerability,
    parse_package_lock,
    parse_requirements,
    scan_dependencies,
    vulnerability_to_secuvanta_finding,
)


class TestDependencyScanner(unittest.TestCase):

    def test_oversized_requirements_manifest_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"
            from core.dependency_scanner import (
                MAX_DEPENDENCY_MANIFEST_SIZE,
            )

            path.write_bytes(
                b"x" * (MAX_DEPENDENCY_MANIFEST_SIZE + 1)
            )

            dependencies = parse_requirements(path)

            self.assertEqual(dependencies, [])

    def test_oversized_package_lock_manifest_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package-lock.json"
            from core.dependency_scanner import (
                MAX_DEPENDENCY_MANIFEST_SIZE,
            )

            path.write_bytes(
                b"x" * (MAX_DEPENDENCY_MANIFEST_SIZE + 1)
            )

            dependencies = parse_package_lock(path)

            self.assertEqual(dependencies, [])

    def test_requirements_parser(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "requirements.txt"

            path.write_text(
                """
# comment
requests==2.31.0
flask~=3.0
psycopg[binary]>=3.2,<4
urllib3
requests==2.31.0  # duplicate
                """.strip(),
                encoding="utf-8",
            )

            dependencies = parse_requirements(path)

            self.assertEqual(
                len(dependencies),
                5,
            )

            exact = dependencies[0]

            self.assertEqual(
                exact["name"],
                "requests",
            )

            self.assertEqual(
                exact["version"],
                "2.31.0",
            )

            self.assertEqual(
                exact["resolution_status"],
                "exact",
            )

            ranged = dependencies[1]

            self.assertEqual(
                ranged["name"],
                "flask",
            )

            self.assertIsNone(
                ranged["version"]
            )

            self.assertEqual(
                ranged["resolution_status"],
                "unresolved",
            )

            extra_dependency = dependencies[2]

            self.assertEqual(
                extra_dependency["name"],
                "psycopg",
            )

            self.assertEqual(
                extra_dependency["version_specifier"],
                ">=3.2,<4",
            )

    def test_package_lock_parser(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "package-lock.json"

            path.write_text(
                """
{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0"
    },
    "node_modules/express": {
      "version": "4.19.2"
    },
    "node_modules/@scope/example": {
      "version": "2.4.1"
    }
  }
}
                """.strip(),
                encoding="utf-8",
            )

            dependencies = parse_package_lock(path)

            self.assertEqual(
                len(dependencies),
                2,
            )

            names = {
                dependency["name"]
                for dependency in dependencies
            }

            self.assertIn(
                "express",
                names,
            )

            self.assertIn(
                "@scope/example",
                names,
            )


    @patch(
        "core.dependency_scanner.query_osv_vulnerabilities"
    )
    def test_scan_dependencies_counts_lookup_errors(
        self,
        mock_query,
    ):
        mock_query.return_value = {
            "status": "ERROR",
            "vulnerabilities": [],
            "vulnerability_count": 0,
            "error": "OSV service unavailable",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / "requirements.txt").write_text(
                "examplepkg==1.0.0\n",
                encoding="utf-8",
            )

            result = scan_dependencies(str(root))

        self.assertEqual(
            result["summary"]["lookup_errors"],
            1,
        )

        self.assertEqual(
            result["results"][0]["status"],
            "ERROR",
        )

        self.assertEqual(
            result["findings"],
            [],
        )

    def test_oversized_manifest_marks_scan_incomplete(self):
        from core.dependency_scanner import (
            MAX_DEPENDENCY_MANIFEST_SIZE,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "requirements.txt"

            manifest.write_bytes(
                b"x" * (MAX_DEPENDENCY_MANIFEST_SIZE + 1)
            )

            result = scan_dependencies(str(root))

        summary = result["summary"]

        self.assertEqual(summary["total_dependencies"], 0)
        self.assertEqual(summary["skipped_manifests"], 1)
        self.assertTrue(summary["incomplete"])
        self.assertTrue(summary["incomplete_reasons"])

    def test_discover_dependencies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / "requirements.txt").write_text(
                "requests==2.31.0\n",
                encoding="utf-8",
            )

            nested = root / "backend"
            nested.mkdir()

            (nested / "requirements.txt").write_text(
                "flask==3.0.0\n",
                encoding="utf-8",
            )

            dependencies = discover_dependencies(
                str(root)
            )

            self.assertEqual(
                len(dependencies),
                2,
            )

            names = {
                dependency["name"]
                for dependency in dependencies
            }

            self.assertEqual(
                names,
                {
                    "requests",
                    "flask",
                },
            )

    def test_normalize_osv_vulnerability(self):
        raw_vulnerability = {
            "id": "GHSA-test-1234",
            "summary": "Example vulnerability",
            "aliases": [
                "CVE-2026-1234",
                "PYSEC-2026-1234",
            ],
            "database_specific": {
                "severity": "HIGH",
            },
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N",
                }
            ],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {
                                    "introduced": "0"
                                },
                                {
                                    "fixed": "2.5.0"
                                },
                            ],
                        }
                    ]
                }
            ],
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://example.com/advisory",
                }
            ],
        }

        normalized = normalize_osv_vulnerability(
            raw_vulnerability
        )

        self.assertEqual(
            normalized["id"],
            "GHSA-test-1234",
        )

        self.assertEqual(
            normalized["cve"],
            "CVE-2026-1234",
        )

        self.assertEqual(
            normalized["severity"],
            "HIGH",
        )

        self.assertEqual(
            normalized["fixed_versions"],
            ["2.5.0"],
        )

        self.assertEqual(
            len(normalized["references"]),
            1,
        )

    def test_deduplicate_vulnerabilities(self):
        vulnerabilities = [
            {
                "id": "GHSA-abc",
                "summary": "Same vulnerability",
                "aliases": [
                    "CVE-2026-0001",
                ],
                "database_specific": {
                    "severity": "HIGH",
                },
                "affected": [],
                "references": [],
            },
            {
                "id": "PYSEC-2026-0001",
                "summary": "Same vulnerability",
                    "aliases": [
        "CVE-2026-0001",
        "PYSEC-2026-0001",
    ],
                "database_specific": {
                    "severity": "UNKNOWN",
                },
                "affected": [],
                "references": [],
            },
        ]

        deduplicated = (
            deduplicate_vulnerabilities(
                vulnerabilities
            )
        )

        self.assertEqual(
            len(deduplicated),
            1,
        )

        self.assertIn(
    "CVE-2026-0001",
    deduplicated[0]["aliases"],
)

        self.assertEqual(
    deduplicated[0]["id"],
    "GHSA-abc",
)

        self.assertIn(
    "PYSEC-2026-0001",
    deduplicated[0]["aliases"],
)

    def test_vulnerability_to_finding(self):
        dependency = {
            "name": "jinja2",
            "version": "3.1.4",
            "ecosystem": "PyPI",
            "manifest": "/temporary/project/requirements.txt",
            "line_number": 1,
        }

        vulnerability = {
            "id": "GHSA-test",
            "aliases": [
                "CVE-2026-1234",
            ],
            "cve": "CVE-2026-1234",
            "summary": "Example vulnerability",
            "severity": "MODERATE",
            "cvss": [],
            "fixed_versions": [
                "3.1.6",
            ],
            "references": [],
        }

        finding = (
            vulnerability_to_secuvanta_finding(
                dependency,
                vulnerability,
                fingerprint_file_path=(
                    "requirements.txt"
                ),
            )
        )

        self.assertEqual(
            finding.finding_type,
            "DEPENDENCY_VULNERABILITY",
        )

        self.assertEqual(
            finding.severity,
            "MEDIUM",
        )

        self.assertEqual(
            finding.file_path,
            dependency["manifest"],
        )

        self.assertEqual(
            finding.line_number,
            1,
        )

        self.assertIn(
            "CVE-2026-1234",
            finding.value,
        )

        self.assertTrue(
            finding.fingerprint
        )

    def test_dependency_fingerprint_is_stable(self):
        dependency_a = {
            "name": "jinja2",
            "version": "3.1.4",
            "ecosystem": "PyPI",
            "manifest": (
                "C:/temp/a/requirements.txt"
            ),
            "line_number": 1,
        }

        dependency_b = {
            "name": "jinja2",
            "version": "3.1.4",
            "ecosystem": "PyPI",
            "manifest": (
                "C:/temp/b/requirements.txt"
            ),
            "line_number": 1,
        }

        vulnerability = {
            "id": "GHSA-test",
            "aliases": [
                "CVE-2026-1234",
            ],
            "cve": "CVE-2026-1234",
            "summary": "Example",
            "severity": "HIGH",
            "cvss": [],
            "fixed_versions": [
                "3.1.6",
            ],
            "references": [],
        }

        finding_a = (
            vulnerability_to_secuvanta_finding(
                dependency_a,
                vulnerability,
                fingerprint_file_path=(
                    "requirements.txt"
                ),
            )
        )

        finding_b = (
            vulnerability_to_secuvanta_finding(
                dependency_b,
                vulnerability,
                fingerprint_file_path=(
                    "requirements.txt"
                ),
            )
        )

        self.assertEqual(
            finding_a.fingerprint,
            finding_b.fingerprint,
        )

    @patch(
        "core.dependency_scanner.query_osv_vulnerabilities"
    )
    def test_scan_dependencies(
        self,
        mock_query,
    ):
        mock_query.return_value = {
            "status": "SUCCESS",
            "vulnerabilities": [
                {
                    "id": "GHSA-test",
                    "summary": "Example vulnerability",
                    "aliases": [
                        "CVE-2026-1234",
                    ],
                    "database_specific": {
                        "severity": "HIGH",
                    },
                    "severity": [
                        {
                            "type": "CVSS_V4",
                            "score": "CVSS:4.0/AV:N",
                        }
                    ],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {
                                            "introduced": "0"
                                        },
                                        {
                                            "fixed": "2.0.0"
                                        },
                                    ],
                                }
                            ]
                        }
                    ],
                    "references": [],
                }
            ],
            "vulnerability_count": 1,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "requirements.txt"
            ).write_text(
                "examplepkg==1.0.0\n",
                encoding="utf-8",
            )

            result = scan_dependencies(
                str(root)
            )

        self.assertEqual(
            result["summary"]["total_dependencies"],
            1,
        )

        self.assertEqual(
            result["summary"]["vulnerable_dependencies"],
            1,
        )

        self.assertEqual(
            result["summary"]["total_vulnerabilities"],
            1,
        )

        self.assertEqual(
            result["summary"]["unresolved_dependencies"],
            0,
        )

        self.assertEqual(
            result["summary"]["lookup_errors"],
            0,
        )

        self.assertEqual(
            len(result["findings"]),
            1,
        )

        self.assertEqual(
            result["findings"][0].finding_type,
            "DEPENDENCY_VULNERABILITY",
        )

        mock_query.assert_called_once()


if __name__ == "__main__":
    unittest.main()