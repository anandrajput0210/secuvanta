# =========================================================
# SECUVANTA FINDING STATUS ENGINE
# =========================================================


# =========================================================
# VALID FINDING STATUSES
# =========================================================

OPEN = "OPEN"

RESOLVED = "RESOLVED"

IGNORED = "IGNORED"


VALID_STATUSES = {

    OPEN,

    RESOLVED,

    IGNORED,

}


# =========================================================
# GET FINDING STATUS
# =========================================================

def get_finding_status(finding):

    """
    Return the status of a finding.

    New findings are OPEN by default.
    """

    status = finding.get(

        "status",

        OPEN

    )

    status = str(status).upper()


    if status not in VALID_STATUSES:

        return OPEN


    return status


# =========================================================
# SET FINDING STATUS
# =========================================================

def set_finding_status(finding, status):

    """
    Update the status of a finding.
    """

    status = str(status).upper()


    if status not in VALID_STATUSES:

        raise ValueError(

            f"Invalid finding status: {status}"

        )


    finding["status"] = status


    return finding


# =========================================================
# COUNT FINDINGS BY STATUS
# =========================================================

def count_findings_by_status(findings):

    """
    Count findings based on their status.
    """

    counts = {

        OPEN: 0,

        RESOLVED: 0,

        IGNORED: 0,

    }


    for finding in findings:

        status = get_finding_status(

            finding

        )


        counts[status] += 1


    return counts


# =========================================================
# CHECK IF FINDING IS ACTIVE
# =========================================================

def is_active_finding(finding):

    """
    A finding is considered active
    when its status is OPEN.
    """

    return (

        get_finding_status(finding)

        == OPEN

    )