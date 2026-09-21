# =========================================================
# SECUVANTA LIVE PROTECTION ORCHESTRATOR
# =========================================================

from pathlib import Path
import uuid

from core.live_monitor import watch
from core.live_events import add_live_event

from core.live_self_action import (
    register_self_action,
    consume_self_action,
)
from core.live_detection import (
    analyze_changed_file,
)

from core.auto_protect import (
    protect_finding,
)

from core.protection_policy import (
    MONITOR,
    GUARDED,
    AUTO_PROTECT,
    CONTAIN,
)


# =========================================================
# EVENT HANDLER
# =========================================================

def handle_event(
    event,
    protection_mode,
):
    """
    Handle one live filesystem event.

    Detection and policy evaluation happen first.
    Automatic containment is executed only when the
    policy explicitly permits it.

    All automatic actions are backup-first and verified.
    """

    event_id = str(uuid.uuid4())
    event_type = event.get(
        "event",
        "UNKNOWN",
    )

    file_path = event.get(
        "file_path",
    )
        # =====================================================
    # SECUVANTA SELF-ACTION
    # =====================================================

    if (
        event_type == "MODIFIED"
        and file_path
        and consume_self_action(
            file_path
        )
    ):

        print()
        print(
            "SecuVanta self-action detected."
        )

        print(
            "Filesystem event suppressed."
        )

        return
        # Record the live filesystem event.
    add_live_event(
    {
        "type": "FILESYSTEM_EVENT",
        "event": event_type,
        "file_path": file_path,
        "mode": protection_mode,
        "event_id": event_id,
    }
)

    print()
    print("=" * 64)
    print("SECUVANTA LIVE EVENT")
    print("=" * 64)

    print(
        "Event:",
        event_type,
    )

    print(
        "File:",
        file_path,
    )

    print(
        "Mode:",
        protection_mode,
    )


    # =====================================================
    # DELETED FILE
    # =====================================================

    if event_type == "DELETED":

        print()
        print(
            "Status: File deleted."
        )

        print(
            "No content available for analysis."
        )

        return


    # =====================================================
    # ANALYZE CHANGED FILE
    # =====================================================

    result = analyze_changed_file(
        file_path,
        protection_mode,
    )


    if not result.get("success"):

        print()

        print(
            "Analysis failed:",
            result.get(
                "error",
                "Unknown error",
            ),
        )

        return


    findings = result.get(
        "findings",
        [],
    )

    decisions = result.get(
        "decisions",
        [],
    )
    
    # =====================================================
    # NO FINDINGS
    # =====================================================

    if not findings:

        print()

        print(
            "Result: No security findings."
        )

        add_live_event({

            "type":
                "ANALYSIS",

            "event":
                event_type,

            "file_path":
                file_path,

            "mode":
                protection_mode,

            "status":
                "CLEAN",

            "finding_count":
                0,

            "event_id":
                event_id,

        })

        return
    # =====================================================
    # FINDINGS
    # =====================================================

    print()
    print(
        "Findings:",
        len(findings),
    )


    for decision in decisions:

        finding = decision[
        "finding"
    ]

    intelligence = decision[
        "intelligence"
    ]

    policy = decision[
        "policy"
    ]

    # =================================================
    # RECORD SECURITY FINDING
    # =================================================

    add_live_event({

        "type":
            "SECURITY_FINDING",

        "event":
            event_type,

        "file_path":
            finding.file_path,

        "line_number":
            finding.line_number,

        "finding_type":
            finding.finding_type,

        "severity":
            finding.severity,

        "risk":
            intelligence[
                "risk_score"
            ],

        "confidence":
            intelligence[
                "confidence"
            ],

        "exposure":
            intelligence[
                "exposure"
            ],

        "false_positive_risk":
            intelligence[
                "false_positive_risk"
            ],

        "policy_action":
            policy[
                "action"
            ],

        "automatic":
            policy[
                "automatic"
            ],

        "status":
            "DETECTED",

        "mode":
            protection_mode,

        "event_id":
            event_id,
    })

    # =================================================
    # POLICY DECISION
    # =================================================

    add_live_event({

        "type":
            "POLICY_DECISION",

        "event":
            event_type,

        "file_path":
            file_path,

        "finding_type":
            finding.finding_type,

        "severity":
            finding.severity,

        "risk":
            intelligence["risk_score"],

        "confidence":
            intelligence["confidence"],

        "exposure":
            intelligence["exposure"],

        "false_positive_risk":
            intelligence["false_positive_risk"],

        "policy_action":
            policy["action"],

        "automatic":
            policy["automatic"],

        "status":
            "DECIDED",

        "mode":
            protection_mode,

        "event_id":
            event_id,

    })

    print()
    print(
            "Finding:",
            finding.finding_type,
        )

    print(
            "Severity:",
            finding.severity,
        )

    print(
            "Risk:",
            intelligence[
                "risk_score"
            ],
        )

    print(
            "Confidence:",
            intelligence[
                "confidence"
            ],
        )

    print(
            "Exposure:",
            intelligence[
                "exposure"
            ],
        )

    print(
            "False-positive risk:",
            intelligence[
                "false_positive_risk"
            ],
        )

    print(
            "Policy action:",
            policy[
                "action"
            ],
        )

    print(
            "Automatic:",
            policy[
                "automatic"
            ],
        )

    print(
            "Policy reason:",
            policy[
                "reason"
            ],
        )


        # =================================================
        # AUTOMATIC CONTAINMENT
        # =================================================

    if (
            policy["action"] == CONTAIN
            and policy["automatic"] is True
        ):

            print()
            print(
                "🚨 AUTO PROTECTION TRIGGERED"
            )

            print(
                "Creating recovery point..."
            )


            protection_result = protect_finding(
                finding=finding,
                project_root=str(
                    Path(file_path).resolve()
                    .parent.parent.parent
                ),
            )
            add_live_event({

                "type":
                    "AUTO_PROTECTION",

                "event":
                    event_type,

                "file_path":
                    finding.file_path,

                "line_number":
                    finding.line_number,

                "finding_type":
                    finding.finding_type,

                "severity":
                    finding.severity,

                "risk":
                    intelligence[
                        "risk_score"
                    ],

                "confidence":
                    intelligence[
                        "confidence"
                    ],

                "exposure":
                    intelligence[
                        "exposure"
                    ],

                "action":
                    protection_result.get(
                        "action"
                    ),

                "success":
                    protection_result.get(
                        "success",
                        False,
                    ),

                "verification":
                    protection_result.get(
                        "verification",
                        "NOT VERIFIED",
                    ),

                "status":
                    (
                        "CONTAINED"
                        if protection_result.get(
                            "success",
                            False,
                        )
                        else "FAILED"
                    ),

                "mode":
                    protection_mode,
                "event_id":
    event_id,
            })

            print()
            print(
                "Protection result:",
                protection_result.get(
                    "action"
                ),
            )

            print(
                "Success:",
                protection_result.get(
                    "success"
                ),
            )

            print(
                "Verification:",
                protection_result.get(
                    "verification",
                    "NOT VERIFIED",
                ),
            )

            print(
                "Reason:",
                protection_result.get(
                    "reason",
                    "No reason supplied.",
                ),
            )


            if protection_result.get(
                "success"
            ):

                print()
                print(
                    "✓ BACKUP CREATED"
                )

                print(
                    "✓ EXPOSURE CONTAINED"
                )

                print(
                    "✓ VERIFICATION PASSED"
                )
                register_self_action(
                    finding.file_path
                )

            else:

                print()
                print(
                    "⚠ AUTOMATIC PROTECTION "
                    "DID NOT COMPLETE"
                )


        # =================================================
        # NON-AUTOMATIC ACTION
        # =================================================

    else:

            print(
                "No automatic modification performed."
            )


# =========================================================
# START LIVE PROTECTION
# =========================================================

def start_live_protection(
    directory: str,
    protection_mode: str = MONITOR,
    interval: float = 1.0,
):
    """
    Start project-scoped live protection.
    """

    root = Path(
        directory
    ).resolve()


    if not root.exists():

        raise FileNotFoundError(
            f"Directory not found: {directory}"
        )


    if not root.is_dir():

        raise NotADirectoryError(
            f"Not a directory: {directory}"
        )


    print()
    print("=" * 64)
    print("SECUVANTA LIVE PROTECTION")
    print("=" * 64)

    print(
        "Project:",
        root,
    )

    print(
        "Mode:",
        protection_mode,
    )

    print(
        "Interval:",
        interval,
        "seconds",
    )

    print()

    if protection_mode == AUTO_PROTECT:

        print(
            "AUTO PROTECT ENABLED"
        )

        print(
            "Only policy-approved, "
            "very-high-confidence exposures "
            "may be automatically contained."
        )

    elif protection_mode == GUARDED:

        print(
            "GUARDED MODE ENABLED"
        )

    else:

        print(
            "MONITOR MODE ENABLED"
        )


    print()
    print(
        "Protection is active."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()


    watch(
        directory=str(root),

        on_change=lambda event:
            handle_event(
                event,
                protection_mode,
            ),

        interval=interval,
    )