import unittest

from core.models import Finding
from core.risk_engine import (
    calculate_finding_risk,
    calculate_project_risk,
    get_risk_level,
)


def create_finding(
    finding_type="AWS Access Key",
    severity="CRITICAL",
    exposure="CRITICAL",
    variable_name="aws_access_key_id",
):

    return Finding(
        finding_type=finding_type,
        severity=severity,
        file_path="production/config.py",
        line_number=1,
        value="********",
        description="Test finding",
        exposure=exposure,
        variable_name=variable_name,
        context_reasons=[
            "Production context detected."
        ],
    )


class TestRiskEngine(unittest.TestCase):
    def test_dependency_vulnerability_finding(self):

        finding = Finding(
            finding_type="DEPENDENCY_VULNERABILITY",
            severity="MEDIUM",
            file_path="requirements.txt",
            line_number=1,
            value="jinja2@3.1.4 [CVE-2025-27516]",
            description="Known OSV vulnerability",
            context_reasons=[],
        )

        analysis = calculate_finding_risk(
            finding
        )

        self.assertEqual(
            analysis["confidence"],
            "HIGH"
)

        self.assertEqual(
            analysis["false_positive_risk"],
            "LOW"
)

    def test_no_findings(self):

        analysis = calculate_project_risk([])

        self.assertEqual(
            analysis["risk_score"],
            0
        )

        self.assertEqual(
            analysis["risk_level"],
            "SAFE"
        )

    def test_critical_aws_finding(self):

        finding = create_finding()

        analysis =calculate_finding_risk(
                finding
            )

        self.assertEqual(
            analysis["confidence"],
            "VERY_HIGH"
        )

        self.assertEqual(
            analysis["exposure"],
            "CRITICAL"
        )

        self.assertEqual(
            analysis["risk_score"],
            100
        )

    def test_project_risk_is_capped(self):

        findings = [
            create_finding()
            for _ in range(5)
        ]

        result = calculate_project_risk(
            findings
        )

        self.assertLessEqual(
            result["risk_score"],
            100
        )

        self.assertEqual(
            result["risk_level"],
            "CRITICAL"
        )

    def test_risk_levels(self):

        self.assertEqual(
            get_risk_level(0),
            "SAFE"
        )

        self.assertEqual(
            get_risk_level(20),
            "MEDIUM"
        )

        self.assertEqual(
            get_risk_level(50),
            "HIGH"
        )

        self.assertEqual(
            get_risk_level(80),
            "CRITICAL"
        )


if __name__ == "__main__":
    unittest.main()