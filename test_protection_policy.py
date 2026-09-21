from core.protection_policy import (
    MONITOR,
    GUARDED,
    AUTO_PROTECT,
    decide_action,
)


tests = [

    (
        "Monitor mode",
        MONITOR,
        "CRITICAL",
        "VERY_HIGH",
        "CRITICAL",
        "LOW",
    ),

    (
        "Guarded mode",
        GUARDED,
        "CRITICAL",
        "VERY_HIGH",
        "CRITICAL",
        "LOW",
    ),

    (
        "Auto protect production",
        AUTO_PROTECT,
        "CRITICAL",
        "VERY_HIGH",
        "CRITICAL",
        "LOW",
    ),

    (
        "Auto protect uncertain finding",
        AUTO_PROTECT,
        "CRITICAL",
        "HIGH",
        "CRITICAL",
        "LOW",
    ),

    (
        "Auto protect high false positive",
        AUTO_PROTECT,
        "CRITICAL",
        "VERY_HIGH",
        "CRITICAL",
        "HIGH",
    ),

    (
        "Auto protect test context",
        AUTO_PROTECT,
        "CRITICAL",
        "VERY_HIGH",
        "LOW",
        "LOW",
    ),
]


for name, mode, severity, confidence, exposure, fp in tests:

    result = decide_action(
        mode=mode,
        severity=severity,
        confidence=confidence,
        exposure=exposure,
        false_positive_risk=fp,
    )

    print()
    print("=" * 60)
    print(name)
    print("=" * 60)

    print("Mode:", mode)
    print("Action:", result["action"])
    print("Automatic:", result["automatic"])
    print("Reason:", result["reason"])