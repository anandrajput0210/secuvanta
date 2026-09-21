from core.analytics import calculate_security_posture


# =========================================================
# TEST 1 — NO HISTORY
# =========================================================

result = calculate_security_posture([])

print("\nTEST 1 — NO HISTORY")
print(result)

assert result["posture"] == "NO_DATA"
assert result["posture_score"] == 0

print("PASS")


# =========================================================
# TEST 2 — IMPROVING
# =========================================================

history = [
    {
        "risk_score": 30,
        "lifecycle_summary": {
            "new": 0,
            "persistent": 1,
            "reappeared": 0,
            "resolved": 2
        }
    },
    {
        "risk_score": 60
    }
]

result = calculate_security_posture(history)

print("\nTEST 2 — IMPROVING")
print(result)

assert result["risk_change"] == -30
assert result["posture_trend"] == "IMPROVING"

print("PASS")


# =========================================================
# TEST 3 — WORSENING
# =========================================================

history = [
    {
        "risk_score": 70,
        "lifecycle_summary": {
            "new": 2,
            "persistent": 1,
            "reappeared": 0,
            "resolved": 0
        }
    },
    {
        "risk_score": 40
    }
]

result = calculate_security_posture(history)

print("\nTEST 3 — WORSENING")
print(result)

assert result["risk_change"] == 30
assert result["posture_trend"] == "WORSENING"

print("PASS")


# =========================================================
# TEST 4 — REAPPEARED
# =========================================================

history = [
    {
        "risk_score": 50,
        "lifecycle_summary": {
            "new": 0,
            "persistent": 0,
            "reappeared": 1,
            "resolved": 0
        }
    },
    {
        "risk_score": 45
    }
]

result = calculate_security_posture(history)

print("\nTEST 4 — REAPPEARED")
print(result)

assert result["reappeared_findings"] == 1
assert "reappeared" in result["explanation"]

print("PASS")


# =========================================================
# TEST 5 — SCORE CANNOT EXCEED 100
# =========================================================

history = [
    {
        "risk_score": 0,
        "lifecycle_summary": {
            "new": 0,
            "persistent": 0,
            "reappeared": 0,
            "resolved": 10
        }
    },
    {
        "risk_score": 50
    }
]

result = calculate_security_posture(history)

print("\nTEST 5 — UPPER LIMIT")
print(result["posture_score"])

assert result["posture_score"] == 100

print("PASS")


# =========================================================
# TEST 6 — SCORE CANNOT GO BELOW 0
# =========================================================

history = [
    {
        "risk_score": 100,
        "lifecycle_summary": {
            "new": 20,
            "persistent": 20,
            "reappeared": 10,
            "resolved": 0
        }
    },
    {
        "risk_score": 50
    }
]

result = calculate_security_posture(history)

print("\nTEST 6 — LOWER LIMIT")
print(result["posture_score"])

assert result["posture_score"] == 0

print("PASS")


# =========================================================
# ALL TESTS PASSED
# =========================================================

print("\n====================================")
print("ALL SECURITY POSTURE TESTS PASSED")
print("====================================")