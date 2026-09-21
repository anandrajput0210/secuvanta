import unittest

from core.lifecycle import analyze_lifecycle
from core.models import NEW, PERSISTENT, REAPPEARED, RESOLVED, OPEN


class TestLifecycle(unittest.TestCase):

    def finding(self, fingerprint="fp-1", **overrides):
        finding = {
            "fingerprint": fingerprint,
            "status": OPEN,
            "lifecycle": NEW,
            "first_seen": "2026-09-13T10:00:00",
            "last_seen": "2026-09-13T10:00:00",
            "times_seen": 1,
        }
        finding.update(overrides)
        return finding

    def test_new_then_persistent(self):
        first = analyze_lifecycle(
            previous_findings=[],
            current_findings=[self.finding()],
        )

        self.assertEqual(first["summary"]["new"], 1)
        self.assertEqual(first["current_findings"][0]["lifecycle"], NEW)
        self.assertEqual(first["current_findings"][0]["times_seen"], 1)

        second = analyze_lifecycle(
            previous_findings=first["current_findings"],
            current_findings=[self.finding()],
            historical_findings=first["current_findings"],
        )

        self.assertEqual(second["summary"]["persistent"], 1)
        self.assertEqual(second["current_findings"][0]["lifecycle"], PERSISTENT)
        self.assertEqual(second["current_findings"][0]["times_seen"], 2)

    def test_missing_finding_becomes_resolved(self):
        previous = self.finding()

        result = analyze_lifecycle(
            previous_findings=[previous],
            current_findings=[],
            historical_findings=[previous],
        )

        self.assertEqual(result["summary"]["resolved"], 1)
        self.assertEqual(result["resolved_findings"][0]["status"], RESOLVED)
        self.assertEqual(
            result["resolved_findings"][0]["lifecycle"],
            RESOLVED,
        )

    def test_resolved_finding_reappears(self):
        # Scan A: finding is first discovered.
        scan_a = analyze_lifecycle(
            previous_findings=[],
            current_findings=[self.finding()],
        )
        active = scan_a["current_findings"][0]

        # Scan B: finding disappears and is marked resolved.
        scan_b = analyze_lifecycle(
            previous_findings=[active],
            current_findings=[],
            historical_findings=[active],
        )
        resolved = scan_b["resolved_findings"][0]

        # Scan C: exact fingerprint returns after being resolved.
        scan_c = analyze_lifecycle(
            previous_findings=[],
            current_findings=[self.finding()],
            historical_findings=[resolved],
        )

        current = scan_c["current_findings"][0]

        self.assertEqual(scan_c["summary"]["new"], 0)
        self.assertEqual(scan_c["summary"]["reappeared"], 1)
        self.assertEqual(current["lifecycle"], REAPPEARED)
        self.assertEqual(current["status"], OPEN)
        self.assertEqual(current["times_seen"], 2)
        self.assertEqual(
            current["first_seen"],
            active["first_seen"],
        )

    def test_reappeared_then_persistent(self):
        resolved = self.finding(
            status=RESOLVED,
            lifecycle=RESOLVED,
            times_seen=4,
        )

        reappeared = analyze_lifecycle(
            previous_findings=[],
            current_findings=[self.finding()],
            historical_findings=[resolved],
        )

        reappeared_finding = reappeared["current_findings"][0]

        self.assertEqual(reappeared_finding["lifecycle"], REAPPEARED)
        self.assertEqual(reappeared_finding["times_seen"], 5)

        persistent = analyze_lifecycle(
            previous_findings=[reappeared_finding],
            current_findings=[self.finding()],
            historical_findings=[reappeared_finding],
        )

        persistent_finding = persistent["current_findings"][0]
        self.assertEqual(persistent_finding["lifecycle"], PERSISTENT)
        self.assertEqual(persistent_finding["times_seen"], 6)


if __name__ == "__main__":
    unittest.main()
