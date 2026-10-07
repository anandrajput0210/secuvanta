import time
import uuid
import json
import sys
import threading
import os
import tempfile
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# =========================================================
# PROJECT PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

WEB_DIRECTORY = PROJECT_ROOT / "web"

sys.path.insert(
    0,
    str(PROJECT_ROOT)
)
# =========================================================
# IMPORTS
# =========================================================

from core.scanner import scan_directory
from core.dependency_scanner import scan_dependencies

from core.history import (
    add_scan,
    get_history,
    get_scan,
    normalize_project_id,
)
from core.live_events import (
    get_live_events,
)

from core.risk_engine import calculate_project_risk

from core.analytics import calculate_analytics, calculate_security_posture

from core.lifecycle import analyze_lifecycle

from core.change_engine import calculate_change

from core.live_protection import start_live_protection
from core.upload_service import (
    MAX_UPLOAD_SIZE,
    cleanup_upload,
    extract_zip_safely,
)
# =========================================================
# SECUVANTA SERVER
# =========================================================

class SecuVantaHandler(SimpleHTTPRequestHandler):


    # =====================================================
    # INITIALIZE SERVER
    # =====================================================

    def __init__(self, *args, **kwargs):

        super().__init__(
            *args,
            directory=str(WEB_DIRECTORY),
            **kwargs
        )


    # =====================================================
    # HANDLE GET REQUESTS
    # =====================================================

    def do_GET(self):

        print(f"\nREQUEST RECEIVED: {self.path}")

        parsed_url = urlparse(self.path)

        print(f"PATH: {parsed_url.path}")


        # =================================================
        # HEALTH API
        # =================================================

        if parsed_url.path == "/api/health":

            print("HEALTH API CALLED")

            self.send_json({
                "success": True,
                "status": "online",
                "service": "SecuVanta",
                "version": "1.0.0"
            })

            return


        # =================================================
        # SCAN API
        # =================================================

        if parsed_url.path == "/api/scan":

            print("SCAN API CALLED")

            parameters = parse_qs(
                parsed_url.query
            )

            target = parameters.get(
                "path",
                ["demo_project"]
            )[0]

            self.run_scan(target)

            return
        # =================================================
        # SECURITY ANALYTICS API
        # =================================================

        if parsed_url.path == "/api/analytics":

            print("ANALYTICS API CALLED")

            parameters = parse_qs(
                parsed_url.query
            )

            project_id = parameters.get(
                "project",
                [None]
            )[0]

            history = (
                get_history(project_id)
                if project_id
                else get_history()
            )

            analytics = calculate_analytics(
                history
            )

            posture = calculate_security_posture(
                history
            )

            self.send_json({
                "success": True,
                "project_id": project_id,
                "analytics": analytics,
                "security_posture": posture
            })

            return
        # =================================================
        # LIVE EVENTS API
        # =================================================

        if parsed_url.path == "/api/live-events":

            self.send_json({
                "success": True,
                "events": get_live_events(25),
            })

            return
        # =================================================
        # SCAN HISTORY API
        # =================================================

        if parsed_url.path == "/api/history":

            print("HISTORY API CALLED")

            parameters = parse_qs(
                parsed_url.query
            )

            project_id = parameters.get(
    "project",
    [None]
)[0]

            history = (
    get_history(project_id)
    if project_id
    else get_history()
)

            self.send_json({
    "success": True,
    "project_id": project_id,
    "history": history
})

            return
                # =================================================
        # SINGLE HISTORICAL SCAN API
        # =================================================

        if parsed_url.path.startswith("/api/history/"):

            print("SINGLE HISTORY API CALLED")

            scan_id = parsed_url.path.replace(
                "/api/history/",
                "",
                1
            )

            parameters = parse_qs(
                parsed_url.query
            )

            project_id = parameters.get(
                "project",
                [None]
            )[0]

            scan = get_scan(
                scan_id,
                project_id
            )

            if scan is None:

                self.send_json(
                    {
                        "success": False,
                        "error": "Scan not found"
                    },
                    status=404
                )

                return

            self.send_json({
                "success": True,
                "project_id": project_id,
                "scan": scan
            })

            return
        # =================================================
        # STATIC WEBSITE
        # =================================================

        print("SERVING STATIC FILE")

        return super().do_GET()
    # =====================================================
    # HANDLE POST REQUESTS
    # =====================================================

    def do_POST(self):

        print(f"\nPOST REQUEST RECEIVED: {self.path}")

        parsed_url = urlparse(self.path)


        # =================================================
        # PROJECT UPLOAD API
        # =================================================

        if parsed_url.path == "/api/upload-project":

            print("PROJECT UPLOAD API CALLED")

            parameters = parse_qs(parsed_url.query)

            project_id = normalize_project_id(
                parameters.get(
                    "project",
                    ["uploaded_project"]
    )[0]
)


            # -------------------------------------------------
            # CHECK CONTENT TYPE
            # -------------------------------------------------

            content_type = self.headers.get(
                "Content-Type",
                ""
            ).lower()


            if (
                "application/zip"
                not in content_type
            ):

                self.send_json(
                    {
                        "success": False,
                        "error":
                            "Only ZIP project uploads are supported."
                    },
                    status=400
                )

                return


            # -------------------------------------------------
            # CHECK CONTENT LENGTH
            # -------------------------------------------------

            content_length = self.headers.get(
                "Content-Length"
            )


            if content_length is None:

                self.send_json(
                    {
                        "success": False,
                        "error":
                            "Content-Length header is required."
                    },
                    status=411
                )

                return


            try:

                upload_size = int(
                    content_length
                )

            except ValueError:

                self.send_json(
                    {
                        "success": False,
                        "error":
                            "Invalid Content-Length header."
                    },
                    status=400
                )

                return


            if upload_size <= 0:

                self.send_json(
                    {
                        "success": False,
                        "error":
                            "Uploaded ZIP is empty."
                    },
                    status=400
                )

                return


            if upload_size > MAX_UPLOAD_SIZE:

                self.send_json(
                    {
                        "success": False,
                        "error":
                            "Uploaded ZIP exceeds the maximum allowed size."
                    },
                    status=413
                )

                return


            # -------------------------------------------------
            # SAVE UPLOAD TO TEMPORARY FILE
            # -------------------------------------------------

            temporary_file = None

            try:

                temporary_file = tempfile.NamedTemporaryFile(
                    prefix="secuvanta_upload_",
                    suffix=".zip",
                    delete=False
                )

                remaining = upload_size


                while remaining > 0:

                    chunk = self.rfile.read(
                        min(
                            1024 * 1024,
                            remaining
                        )
                    )

                    if not chunk:

                        raise ValueError(
                            "Upload ended before the expected size was received."
                        )

                    temporary_file.write(
                        chunk
                    )

                    remaining -= len(
                        chunk
                    )


                temporary_file.close()

                temporary_zip = Path(
                    temporary_file.name
                )

                # -------------------------------------------------
                # VALIDATE, EXTRACT AND SCAN
                # -------------------------------------------------

                extracted_project = None

                try:

                    extracted_project = extract_zip_safely(
                        temporary_zip
                    )

                    print(
                        f"UPLOAD WORKSPACE: {extracted_project}"
                    )


                    # -------------------------------------------------
                    # RUN EXISTING SECUVANTA SCAN PIPELINE
                    # -------------------------------------------------

                    self.run_scan(
                        str(extracted_project),
                        fingerprint_root=str(extracted_project),
                        project_id=project_id,
                    )
                    return


                finally:

                    # -------------------------------------------------
                    # CLEAN TEMPORARY ZIP
                    # -------------------------------------------------

                    temporary_zip.unlink(
                        missing_ok=True
                    )


                    # -------------------------------------------------
                    # CLEAN ISOLATED WORKSPACE
                    # -------------------------------------------------

                    if extracted_project is not None:

                        cleanup_upload(
                            extracted_project.parent
                        )
            except Exception as error:

                print(
                    f"UPLOAD ERROR: {error}"
                )


                if temporary_file is not None:

                    try:
                        temporary_file.close()
                    except Exception:
                        pass


                if (
                    temporary_file is not None
                    and temporary_file.name
                ):

                    try:
                        Path(
                            temporary_file.name
                        ).unlink(
                            missing_ok=True
                        )
                    except OSError:
                        pass


                self.send_json(
                    {
                        "success": False,
                        "error": str(error)
                    },
                    status=400
                )

                return

    # =====================================================
    # RUN SECURITY SCAN
    # =====================================================

    def run_scan(
        self,
        target,
        fingerprint_root=None,
        project_id=None,
    ):
        try:

            # -------------------------------------------------
            # START TIMER
            # -------------------------------------------------

            scan_started = time.perf_counter()


            # -------------------------------------------------
            # RESOLVE TARGET PATH
            # -------------------------------------------------

            target_path = Path(target)

            if not target_path.is_absolute():

                target_path = PROJECT_ROOT / target_path


            target_path = target_path.resolve()

            project_root = (
                PROJECT_ROOT.resolve()
            )

            temporary_root = (
                Path(
                    tempfile.gettempdir()
                ).resolve()
            )

            is_project_path = True

            try:

                target_path.relative_to(
                    project_root
                )

            except ValueError:

                is_project_path = False


            is_upload_workspace = False

            if not is_project_path:

                try:

                    upload_parent = (
                        target_path.parent
                    )

                    upload_parent.relative_to(
                        temporary_root
                    )

                    is_upload_workspace = (
                        project_id is not None
                        and fingerprint_root is not None
                        and upload_parent.name.startswith(
                        "secuvanta_upload_"
                        )
                        and target_path.name == "project"
                    )
                except ValueError:

                    is_upload_workspace = False


            if not (
                is_project_path
                or is_upload_workspace
            ):

                raise PermissionError(
                    "Scanning directories outside "
                    "SecuVanta project or isolated "
                    "upload workspaces is not allowed."
                )
            # -------------------------------------------------
            # RUN SCANNER
            # -------------------------------------------------
            scan_result = scan_directory(
                str(target_path),
                fingerprint_root=fingerprint_root,
            )

            findings = scan_result["findings"]

            # -------------------------------------------------
            # DEPENDENCY VULNERABILITY SCAN
            # -------------------------------------------------

            dependency_result = scan_dependencies(
                str(target_path),
                fingerprint_root=fingerprint_root,
            )

            findings.extend(
                dependency_result["findings"]
            )

            files_scanned = scan_result["files_scanned"]

            files_skipped = scan_result["files_skipped"]

            files_failed = scan_result["files_failed"]

            skipped_files = scan_result["skipped_files"]

            failed_files = scan_result["failed_files"]
            # -------------------------------------------------
            # BUILD SEVERITY SUMMARY
            # -------------------------------------------------

            severity_summary = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }


            for finding in findings:

                severity = finding.severity.upper()

                if severity in severity_summary:

                    severity_summary[severity] += 1


            # =================================================
            # SecuVanta INTELLIGENT RISK ANALYSIS
            # =================================================

            risk_analysis = calculate_project_risk(
                findings
            )


            risk_score = (
                risk_analysis["risk_score"]
            )


            risk_level = (
                risk_analysis["risk_level"]
            )


            analyzed_findings = (
                risk_analysis["findings"]
            )
            # =================================================
            # PREPARE FINDINGS FOR API
            # =================================================

            serialized_findings = []

            for analyzed_finding in analyzed_findings:

                finding = analyzed_finding["finding"]

                intelligence = analyzed_finding["intelligence"]

                serialized_findings.append({

                    # -----------------------------------------
                    # BASIC FINDING INFORMATION
                    # -----------------------------------------

                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "value": finding.value,
                    "description": finding.description,
                    "entropy": finding.entropy,

                    # -----------------------------------------
                    # STABLE FINDING IDENTITY
                    # -----------------------------------------

                    "fingerprint": finding.fingerprint,

                    # -----------------------------------------
                    # DEFAULT STATUS
                    # -----------------------------------------

                    "status": "OPEN",

                    # -----------------------------------------
                    # INITIAL LIFECYCLE
                    # -----------------------------------------

                    "lifecycle": "NEW",
                    "first_seen": None,
                    "last_seen": None,
                    "times_seen": 1,

                    # -----------------------------------------
                    # SECURITY INTELLIGENCE
                    # -----------------------------------------

                    "risk_contribution":
                        intelligence["risk_score"],

                    "confidence":
                        intelligence["confidence"],

                    "confidence_score":
                        intelligence["confidence_score"],

                    "exposure":
                        intelligence["exposure"],

                    "false_positive_risk":
                        intelligence["false_positive_risk"],
                        "exposure_score":
    intelligence["exposure_score"],

"variable_name":
    finding.variable_name,

"context_reasons":
    finding.context_reasons or [],

"risk_reasons":
    intelligence["risk_reasons"],
                })


            # =================================================
            # FINDING LIFECYCLE ANALYSIS
            # =================================================

            history = get_history()

            current_target = str(target_path)

            previous_scan = None


            def is_same_history_project(historical_scan):

                if project_id:
                    return (
                        historical_scan.get("project_id")
                        == project_id
                    )

                return (
                    historical_scan.get("target_resolved")
                    == current_target
                )


# Find the most recent scan of the SAME project.
            for historical_scan in history:

                if is_same_history_project(
                    historical_scan
                ):
                    previous_scan = historical_scan
                    break


            previous_findings = []

            if previous_scan:

                previous_findings = previous_scan.get(
                    "findings",
                    []
                )

            # -------------------------------------------------
            # BUILD MOST-RECENT HISTORICAL STATE
            # -------------------------------------------------
            # Walk history from newest to oldest and keep the first
            # occurrence of each fingerprint. This gives lifecycle.py
            # the latest known state even when a finding disappeared
            # in an earlier scan and has just returned now.
            historical_state = {}


            for historical_scan in history:

                if project_id:
                    if historical_scan.get("project_id") != project_id:
                        continue
                else:
                    if historical_scan.get("target_resolved") != current_target:
                        continue

                historical_findings = historical_scan.get(
                    "findings",
                    []
                )

                historical_resolved = historical_scan.get(
                    "resolved_findings",
                    []
                )

                for historical_finding in historical_findings:
                    fingerprint = historical_finding.get("fingerprint")

                    if fingerprint and fingerprint not in historical_state:
                        historical_state[fingerprint] = historical_finding

                for resolved_finding in historical_resolved:
                    fingerprint = resolved_finding.get("fingerprint")

                    if fingerprint and fingerprint not in historical_state:
                        historical_state[fingerprint] = resolved_finding


            # Always run lifecycle analysis.
            lifecycle_result = analyze_lifecycle(
                previous_findings=previous_findings,
                current_findings=serialized_findings,
                historical_findings=list(historical_state.values()),
            )


            serialized_findings = (
                lifecycle_result["current_findings"]
            )
    # -------------------------------------------------
# REBUILD SEVERITY SUMMARY FROM FINAL FINDINGS
# -------------------------------------------------

            severity_summary = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
}

            for finding in serialized_findings:

                severity = (
        finding.get("severity", "")
        .upper()
    )

                if severity in severity_summary:
                    severity_summary[severity] += 1

            resolved_findings = (
                lifecycle_result["resolved_findings"]
            )

            lifecycle_summary = (
                lifecycle_result["summary"]
            )
            # -------------------------------------------------
            # CALCULATE SCAN DURATION
            # -------------------------------------------------

            scan_duration = round(

                time.perf_counter()
                - scan_started,

                4
            )


            # -------------------------------------------------
            # CREATE UNIQUE SCAN ID
            # -------------------------------------------------

            scan_id = str(
                uuid.uuid4()
            )


                        # =================================================
            # CREATE HISTORY RECORD
            # =================================================

            history_record = {

                # =============================================
                # SCHEMA
                # =============================================

                "schema_version": 2,

                # =============================================
                # SCAN IDENTITY
                # =============================================

                "scan_id":
                    scan_id,

                "scan_time":
                    datetime.now().astimezone().isoformat(),

                "target":
                    str(target),
                "project_id":
                    project_id,

                "target_resolved":
                    str(target_path),

                # =============================================
                # SCAN PERFORMANCE
                # =============================================

                "scan_duration":
                    scan_duration,

                # =============================================
                # COVERAGE
                # =============================================

                "files_scanned":
                    files_scanned,

                "files_skipped":
                    files_skipped,

                "files_failed":
                    files_failed,

                "skipped_files":
                    skipped_files,

                "failed_files":
                    failed_files,

                # =============================================
                # FINDING SUMMARY
                # =============================================

                "total_findings":
                    len(serialized_findings),

                "lifecycle_summary":
                    lifecycle_summary,

                # =============================================
                # RISK
                # =============================================

                "risk_score":
                    risk_score,

                "risk_level":
                    risk_level,

                "severity_summary":
                    severity_summary,

                # =============================================
                # CURRENT FINDINGS
                # =============================================

                "findings":
                    serialized_findings,

                # =============================================
                # RESOLVED FINDINGS
                # =============================================

                "resolved_findings":
                    resolved_findings,
            }


            # =================================================
            # CHANGE INTELLIGENCE
            # =================================================

            change_analysis = calculate_change(
                previous_scan,
                history_record,
            )


            history_record["change_analysis"] = (
                change_analysis
            )


            # =================================================
            # SAVE SCAN TO HISTORY
            # =================================================


            add_scan(
                history_record
            )
            # =================================================
            # BUILD API RESPONSE
            # =================================================

            response = {

                "scan_id":
                    scan_id,

                "success":
                    True,

                "tool":
                    "SecuVanta",

                "version":
                    "1.0.0",

                "scan_time":
                    history_record["scan_time"],

                "scan_duration":
                    scan_duration,

                "target":
                    str(target),

                "lifecycle":
                    lifecycle_summary,

                # ---------------------------------------------
                # CHANGE INTELLIGENCE
                # ---------------------------------------------

                "change_analysis":
                    change_analysis,

                # ---------------------------------------------
                # SCAN SUMMARY
                # ---------------------------------------------

                "summary": {

                    "files_scanned":
                        files_scanned,

                    "files_skipped":
                        files_skipped,

                    "files_failed":
                        files_failed,

                    "total_findings":
                        len(serialized_findings),

                    "risk_score":
                        risk_score,

                    "risk_level":
                        risk_level,

                    "severity_summary":
                        severity_summary,

                    "lifecycle":
                        lifecycle_summary,

                    "risk_change":
                        change_analysis[
                            "risk_change"
                        ],

                    "risk_reduction":
                        change_analysis[
                            "risk_reduction"
                        ],

                    "security_improved":
                        change_analysis[
                            "security_improved"
                        ],
                },

                # ---------------------------------------------
                # COMPLETE FINDINGS
                # ---------------------------------------------

                "findings":
                    serialized_findings,
            }


            self.send_json(
                response
            )



        # =====================================================
        # ERROR: DIRECTORY NOT FOUND
        # =====================================================

        except FileNotFoundError:

            self.send_json(
                {
                    "success": False,
                    "error":
                        f"Directory not found: {target}"
                },
                status=404
            )


        # =====================================================
        # ERROR: NOT A DIRECTORY
        # =====================================================

        except NotADirectoryError:

            self.send_json(
                {
                    "success": False,
                    "error":
                        f"Not a directory: {target}"
                },
                status=400
            )
        # =====================================================
        # ERROR: ACCESS DENIED
        # =====================================================

        except PermissionError:

            self.send_json(
                {
                    "success": False,
                    "error":
                        "Scanning directories outside the SecuVanta project is not allowed."              },
                status=403
            )

        # =====================================================
        # GENERAL ERROR
        # =====================================================

        except Exception as error:

            print(
                f"SERVER ERROR: {error}"
            )

            self.send_json(
                {
                    "success": False,
                    "error": str(error)
                },
                status=500
            )


    # =====================================================
    # SEND JSON RESPONSE
    # =====================================================

    def send_json(self, data, status=200):

        response = json.dumps(
            data,
            indent=2
        ).encode(
            "utf-8"
        )


        self.send_response(
            status
        )


        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )


        self.send_header(
            "Content-Length",
            str(len(response))
        )


        self.send_header(
            "Cache-Control",
            "no-cache"
        )


        self.end_headers()


        self.wfile.write(
            response
        )


# =========================================================
# START SERVER
# =========================================================
def run_server():

    host = "0.0.0.0"

    port = int(
        os.environ.get(
            "PORT",
            "8000"
        )
    )

    server = HTTPServer(

        (
            host,
            port
        ),

        SecuVantaHandler
    )
        # =====================================================
    # START LIVE PROTECTION
    # =====================================================

    project_root = (
        Path(__file__).resolve().parent.parent
        / "demo_project"
    )

    live_thread = threading.Thread(
        target=start_live_protection,
        kwargs={
            "directory": str(project_root),
            "protection_mode": "AUTO_PROTECT",
            "interval": 1.0,
        },
        daemon=True,
    )

    live_thread.start()


    print()

    print("=" * 60)

    print(
        "       SECUVANTA SECURITY CONSOLE"
    )

    print(
        "       Context-Aware Security Intelligence Platform"
    )

    print("=" * 60)

    print()


    print(
        f"Dashboard: http://{host}:{port}"
    )

    print(
        f"Health API: http://{host}:{port}/api/health"
    )

    print(
        f"Scan API: "
        f"http://{host}:{port}/api/scan?path=demo_project"
    )

    print(
        f"History API: "
        f"http://{host}:{port}/api/history"
    )


    print()

    print(
        "Press CTRL+C to stop SecuVanta."
    )

    print()


    try:

        server.serve_forever()


    except KeyboardInterrupt:

        print(
            "\nSecuVanta server stopped."
        )


    finally:

        server.server_close()


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    run_server()