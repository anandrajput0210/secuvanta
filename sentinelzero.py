import argparse
import json
import sys
from datetime import datetime

from core.scanner import scan_directory
from core.risk_engine import analyze_risk


def print_banner():
    print()
    print("=" * 60)
    print("              🛡️  SecuVanta")
    print("       Context-Aware Security Intelligence")
    print("=" * 60)
    print()


def format_finding(finding):
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }

    icon = severity_icons.get(finding.severity, "⚪")

    print(f"{icon} [{finding.severity}] {finding.finding_type}")
    print(f"   File: {finding.file_path}")
    print(f"   Line: {finding.line_number}")
    print(f"   Value: {finding.value}")
    print(f"   Reason: {finding.description}")
    print()


def build_report(target, findings, files_scanned, analysis):
    return {
        "tool": "SecuVanta",
        "version": "1.0.0",
        "scan_time": datetime.now().isoformat(),
        "target": str(target),
        "summary": {
            "files_scanned": files_scanned,
            "total_findings": analysis["total_findings"],
            "risk_score": analysis["score"],
            "risk_level": analysis["level"],
            "severity_summary": analysis["summary"],
        },
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
    }


def run_scan(args):
    print_banner()

    print(f"🔍 Scanning: {args.directory}")
    print()

    try:
        findings, files_scanned = scan_directory(args.directory)

    except (FileNotFoundError, NotADirectoryError) as error:
        print(f"❌ Error: {error}")
        sys.exit(1)

    analysis = analyze_risk(findings)

    print("-" * 60)
    print("SCAN RESULTS")
    print("-" * 60)
    print()

    if findings:
        for finding in findings:
            format_finding(finding)
    else:
        print("✅ No security findings detected.")
        print()

    print("-" * 60)
    print("SECURITY POSTURE")
    print("-" * 60)

    print(f"Files scanned:    {files_scanned}")
    print(f"Total findings:   {analysis['total_findings']}")
    print(f"Risk score:       {analysis['score']}/100")
    print(f"Risk level:       {analysis['level']}")
    print()

    summary = analysis["summary"]

    print(f"🔴 Critical: {summary['CRITICAL']}")
    print(f"🟠 High:     {summary['HIGH']}")
    print(f"🟡 Medium:   {summary['MEDIUM']}")
    print(f"🟢 Low:      {summary['LOW']}")
    print()

    if args.format == "json":
        report = build_report(
            args.directory,
            findings,
            files_scanned,
            analysis,
        )

        print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="SECUVANTA - Zero Dependency Security Scanner"
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory for exposed secrets"
    )

    scan_parser.add_argument(
        "directory",
        help="Directory to scan"
    )

    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()