
// ======================================================
// SECUVANTA DASHBOARD
// Real-Time Security Scanner Integration
// ======================================================

const API_BASE = window.location.origin;

let currentFindings = [];
let currentFilter = "ALL";
// ======================================================
// SIDEBAR NAVIGATION
// ======================================================

document.addEventListener("DOMContentLoaded", () => {

    const navItems = document.querySelectorAll(".nav-item");

    function updateActiveNav() {

        const currentHash = window.location.hash;

        navItems.forEach((item) => {
            item.classList.remove("active");
        });

        if (!currentHash || currentHash === "#") {
            const dashboardItem =
                document.querySelector('.nav-item[href="#"]');

            if (dashboardItem) {
                dashboardItem.classList.add("active");
            }

            return;
        }

        const activeItem =
            document.querySelector(
                `.nav-item[href="${currentHash}"]`
            );

        if (activeItem) {
            activeItem.classList.add("active");
        }
    }

    navItems.forEach((item) => {

        item.addEventListener("click", () => {

            setTimeout(() => {
                updateActiveNav();
            }, 0);

        });

    });

    window.addEventListener(
        "hashchange",
        updateActiveNav
    );

    updateActiveNav();

});
// ======================================================
// SCAN HISTORY
// ======================================================

let scanHistory = [];
// ======================================================
// LIVE PROTECTION
// ======================================================

// ======================================================
// LIVE SECURITY EVENT STREAM
// ======================================================

let liveEvents = [];
let livePollingTimer = null;

async function loadLiveEvents() {

    try {

        const response = await fetch(
            `${API_BASE}/api/live-events?ts=${Date.now()}`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `Live events API returned ${response.status}`
            );
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(
                data.error || "Unable to load live events"
            );
        }

        liveEvents = Array.isArray(data.events)
            ? data.events
            : [];

        renderLiveEvents(liveEvents);

    } catch (error) {

        console.error(
            "Live event polling failed:",
            error
        );
    }
}


// ======================================================
// RENDER LIVE EVENTS
// ======================================================

// ======================================================
// RENDER LIVE INCIDENT TIMELINES
// ======================================================

function renderLiveEvents(events) {

    const list =
        document.getElementById(
            "liveEventList"
        );

    const status =
        document.getElementById(
            "liveProtectionStatus"
        );

    const statusText =
        document.getElementById(
            "liveProtectionStatusText"
        );

    const modeElement =
        document.getElementById(
            "liveProtectionMode"
        );

    const countElement =
        document.getElementById(
            "liveEventCount"
        );

    const lastEventElement =
        document.getElementById(
            "liveLastEvent"
        );


    if (!list) return;


    // ==================================================
    // NORMALIZE EVENTS
    // ==================================================

    const safeEvents =
        Array.isArray(events)
            ? events
            : [];


    // ==================================================
    // GROUP EVENTS INTO INCIDENTS
    //
    // event_id = one filesystem/security incident
    // ==================================================

    const incidentMap =
        new Map();


    safeEvents.forEach(
        (event, index) => {

            /*
             * Older events may not have an event_id.
             * Keep them visible by assigning a local fallback.
             */

            const incidentId =
                event.event_id
                    ? event.event_id
                    : `legacy-${index}-${event.timestamp || ""}`;


            if (!incidentMap.has(incidentId)) {

                incidentMap.set(
                    incidentId,
                    []
                );

            }


            incidentMap
                .get(incidentId)
                .push(event);

        }
    );


    // ==================================================
    // BUILD INCIDENTS
    // ==================================================

    const incidents =
        Array.from(
            incidentMap.entries()
        )
        .map(
            ([eventId, incidentEvents]) => {

                const timeline =
                    [...incidentEvents].sort(
                        (a, b) =>
                            new Date(
                                a.timestamp || 0
                            ) -
                            new Date(
                                b.timestamp || 0
                            )
                    );


                const newest =
                    timeline[
                        timeline.length - 1
                    ] || {};


                const finding =
                    timeline.find(
                        event =>
                            event.type ===
                            "SECURITY_FINDING"
                    ) || {};


                const protection =
                    timeline.find(
                        event =>
                            event.type ===
                            "AUTO_PROTECTION"
                    ) || {};


                const policy =
                    timeline.find(
                        event =>
                            event.type ===
                            "POLICY_DECISION"
                    ) || {};


                const filesystem =
                    timeline.find(
                        event =>
                            event.type ===
                            "FILESYSTEM_EVENT"
                    ) || {};


                return {

                    eventId,

                    timeline,

                    newest,

                    finding,

                    protection,

                    policy,

                    filesystem,

                    timestamp:
                        newest.timestamp ||
                        timeline[0]?.timestamp ||
                        ""

                };

            }
        )
        .sort(
            (a, b) =>
                new Date(b.timestamp || 0) -
                new Date(a.timestamp || 0)
        );


    // ==================================================
    // STATUS
    // ==================================================

    const hasRecentEvents =
        safeEvents.length > 0;


    if (status) {

        status.classList.toggle(
            "active",
            hasRecentEvents
        );

        status.classList.toggle(
            "offline",
            !hasRecentEvents
        );

    }


    if (statusText) {

        statusText.textContent =
            hasRecentEvents
                ? "EVENTS ACTIVE"
                : "WAITING";

    }


    // ==================================================
    // MODE
    // ==================================================

    const latestMode =
        safeEvents.find(
            event => event.mode
        )?.mode;


    if (modeElement) {

        modeElement.textContent =
            latestMode || "—";

    }


    // ==================================================
    // INCIDENT COUNT
    // ==================================================

    if (countElement) {

        countElement.textContent =
            incidents.length;

    }


    // ==================================================
// LAST EVENT
// ==================================================

if (lastEventElement) {

    const latest =
        [...safeEvents].sort(
            (a, b) =>
                new Date(b.timestamp || 0) -
                new Date(a.timestamp || 0)
        )[0] || null;

    lastEventElement.textContent =
        latest
            ? (
                latest.type === "AUTO_PROTECTION" &&
                latest.status === "CONTAINED"
                    ? "CONTAINED"
                    : latest.event ||
                      latest.type ||
                      "EVENT"
            )
            : "—";
}


    // ==================================================
    // EMPTY STATE
    // ==================================================

    if (incidents.length === 0) {

        list.innerHTML = `
            <div class="live-event-empty">
                Waiting for live security incidents...
            </div>
        `;

        return;

    }


    // ==================================================
    // RENDER INCIDENTS
    // ==================================================

    list.innerHTML = "";


    incidents
        .slice(0, 12)
        .forEach(
            incident => {

                const card =
                    document.createElement(
                        "div"
                    );


                const protectionSuccess =
                    incident.protection &&
                    incident.protection.success === true;


                const protectionFailed =
                    incident.protection &&
                    incident.protection.success === false;

const hasFinding =
    Boolean(
        incident.finding &&
        incident.finding.finding_type
    );


const outcome =
    protectionSuccess
        ? "CONTAINED"
        : protectionFailed
            ? "BLOCKED"
            : hasFinding
                ? "DETECTED"
                : "OBSERVED";


const outcomeClass =
    protectionSuccess
        ? "success"
        : protectionFailed
            ? "failed"
            : hasFinding
                ? "danger"
                : "neutral";

                card.className =
                    `incident-card ${outcomeClass}`;


                // --------------------------------------------------
                // INCIDENT INFORMATION
                // --------------------------------------------------

                const shortIncidentId =
                    incident.eventId &&
                    incident.eventId.length > 8
                        ? incident.eventId.slice(0, 8)
                        : incident.eventId;


                const filePath =
    incident.finding.file_path ||
    incident.protection.file_path ||
    incident.policy.file_path ||
    incident.filesystem.file_path ||
    "Project";


                const fileName =
                    typeof getFileName === "function"
                        ? getFileName(filePath)
                        : filePath;


const findingType =
    incident.finding.finding_type ||
    incident.protection.finding_type ||
    incident.policy.finding_type ||
    "No Threat";
                const severity =
    incident.finding.severity ||
    incident.protection.severity ||
    incident.policy.severity ||
    "";


                const risk =
    incident.finding.risk !== undefined
        ? incident.finding.risk
        : incident.finding.risk_score !== undefined
            ? incident.finding.risk_score
            : incident.policy.risk !== undefined
                ? incident.policy.risk
                : incident.policy.risk_score !== undefined
                    ? incident.policy.risk_score
                    : incident.protection.risk !== undefined
                        ? incident.protection.risk
                        : incident.protection.risk_score !== undefined
                            ? incident.protection.risk_score
                            : null;


                const confidence =
    incident.finding.confidence ||
    incident.protection.confidence ||
    incident.policy.confidence ||
    "";


                const exposure =
    incident.finding.exposure ||
    incident.protection.exposure ||
    incident.policy.exposure ||
    "";


                // --------------------------------------------------
                // INCIDENT HEADER
                // --------------------------------------------------

                card.innerHTML = `

                    <div class="incident-header">

                        <div class="incident-heading">

                            <div class="incident-status-dot"></div>

                            <div>

                                <div class="incident-title">
                                    INCIDENT #${escapeHtml(
                                        shortIncidentId || "UNKNOWN"
                                    )}
                                </div>

                                <div class="incident-file">
                                    ${escapeHtml(fileName)}
                                </div>

                            </div>

                        </div>


                        <div class="incident-outcome ${outcomeClass}">
                            ${outcome}
                        </div>

                    </div>


                    <div class="incident-summary">

    <div class="incident-summary-item">
        <span>THREAT</span>
        <strong>
            ${escapeHtml(
                findingType
            )}
        </strong>
    </div>

    <div class="incident-summary-item">
        <span>SEVERITY</span>
        <strong class="${
            severity
                ? "incident-severity-" +
                  severity.toLowerCase()
                : ""
        }">
            ${escapeHtml(
                severity || "—"
            )}
        </strong>
    </div>

    <div class="incident-summary-item">
        <span>RISK</span>
        <strong>
            ${
                risk !== null
                    ? escapeHtml(
                        String(risk)
                    )
                    : "—"
            }
        </strong>
    </div>

    <div class="incident-summary-item">
        <span>EXPOSURE</span>
        <strong>
            ${escapeHtml(
                exposure || "—"
            )}
        </strong>
    </div>

    <div class="incident-summary-item">
        <span>CONFIDENCE</span>
        <strong>
            ${escapeHtml(
                confidence || "—"
            )}
        </strong>
    </div>

    <div class="incident-summary-item">
        <span>ACTION</span>
        <strong>
            ${
                escapeHtml(
                    incident.policy.policy_action ||
                    incident.protection.action ||
                    "MONITOR"
                )
            }
        </strong>
    </div>

</div>


                    <div class="incident-timeline">

                        ${incident.timeline
                            .map(
                                (event, index) =>
                                    renderIncidentTimelineEvent(
                                        event,
                                        index,
                                        incident.timeline.length
                                    )
                            )
                            .join("")}

                    </div>


                    ${
                        protectionSuccess
                            ? `
                                <div class="incident-verification success">

                                    <span class="verification-icon">
                                        ✓
                                    </span>

                                    <div>

                                        <strong>
                                            SECURITY ACTION VERIFIED
                                        </strong>

                                        <span>
    Credential exposure was removed.
    Source rescanned successfully.
    Security state: CONTAINED.
</span>

                                    </div>

                                </div>
                            `
                            : protectionFailed
                                ? `
                                    <div class="incident-verification failed">

                                        <span class="verification-icon">
                                            !
                                        </span>

                                        <div>

                                            <strong>
                                                PROTECTION FAILED
                                            </strong>

                                            <span>
                                                SecuVanta blocked automatic
                                                completion and preserved the incident state.
                                            </span>

                                        </div>

                                    </div>
                                `
                                : ""
                    }

                `;


                list.appendChild(card);

            }
        );

}


// ======================================================
// RENDER ONE TIMELINE EVENT
// ======================================================

function renderIncidentTimelineEvent(
    event,
    index,
    total
) {

    const type =
        event.type || "";


    let title =
        "SECURITY EVENT";


    let description =
        "Security event recorded.";


    let icon =
        "•";


    let eventClass =
        "neutral";


    // ==================================================
    // FILESYSTEM
    // ==================================================

    if (type === "FILESYSTEM_EVENT") {

        const action =
            event.event ||
            "CHANGED";


        title =
            `FILE ${action}`;


        description =
            event.file_path
                ? getFileName(
                    event.file_path
                )
                : "Filesystem change detected";


        icon =
            action === "CREATED"
                ? "+"
                : action === "DELETED"
                    ? "×"
                    : "↻";


        eventClass =
            "filesystem";

    }


    // ==================================================
    // SECURITY FINDING
    // ==================================================

    else if (
        type === "SECURITY_FINDING"
    ) {

        title =
            "SECRET DETECTED";


        description =
            event.finding_type ||
            "Sensitive credential detected";


        if (event.severity) {

            description +=
                ` · ${event.severity}`;

        }


        icon =
            "!";


        eventClass =
            "finding";

    }


    // ==================================================
    // POLICY
    // ==================================================

    else if (
        type === "POLICY_DECISION"
    ) {

        const action =
            event.policy_action ||
            event.action ||
            "ALERT";


        title =
            `POLICY → ${action}`;


        description =
            event.automatic === true
                ? "Automatic protection authorized"
                : "Security response evaluated";


        icon =
            "→";


        eventClass =
            "policy";

    }


    // ==================================================
    // AUTO PROTECTION
    // ==================================================

    else if (
        type === "AUTO_PROTECTION"
    ) {

        title =
            "AUTO-PROTECTION";


        if (event.success === true) {

            description =
                "Backup → Redact → Rescan → Verify";


            icon =
                "✓";


            eventClass =
                "protection-success";

        }

        else {

            description =
                event.error ||
                "Protection action blocked";


            icon =
                "!";


            eventClass =
                "protection-failed";

        }

    }


    // ==================================================
    // ANALYSIS
    // ==================================================

    else if (
        type === "ANALYSIS"
    ) {

        title =
            event.event === "CLEAN"
                ? "ANALYSIS COMPLETE"
                : "FILE ANALYZED";


        description =
            event.status ||
            "Security analysis completed";


        icon =
            "✓";


        eventClass =
            "analysis";

    }


    // ==================================================
    // TIMESTAMP
    // ==================================================

    let time =
        "—";


    if (event.timestamp) {

        const date =
            new Date(
                event.timestamp
            );


        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {

            time =
                date.toLocaleTimeString(
                    [],
                    {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit"
                    }
                );

        }

    }


    const isLast =
        index === total - 1;


    return `

        <div class="
            incident-timeline-event
            ${eventClass}
            ${isLast ? "last" : ""}
        ">

            <div class="timeline-marker">

                <span>
                    ${icon}
                </span>

            </div>


            <div class="timeline-content">

                <div class="timeline-time">
                    ${escapeHtml(time)}
                </div>

                <div class="timeline-title">
                    ${escapeHtml(title)}
                </div>

                <div class="timeline-description">
                    ${escapeHtml(description)}
                </div>

            </div>

        </div>

    `;

}
// ======================================================
// LIVE EVENT TIME
// ======================================================

function formatLiveTime(timestamp) {

    if (!timestamp) {
        return "—";
    }


    const date =
        new Date(timestamp);


    if (isNaN(
        date.getTime()
    )) {

        return "—";
    }


    return date.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        }
    );
}
// ======================================================
// START LIVE POLLING
// ======================================================

function startLivePolling() {

    loadLiveEvents();


    if (livePollingTimer) {
        clearInterval(
            livePollingTimer
        );
    }


    livePollingTimer =
        setInterval(
            loadLiveEvents,
            1000
        );
}


// ======================================================
// DOM ELEMENTS
// ======================================================


const projectZipInput =
    document.getElementById("projectZip");

const riskScoreElement =
    document.getElementById("riskScore");

const securityScoreElement =
    document.getElementById("securityScore");

const securityProgressElement =
    document.getElementById("securityProgress");

const riskTitleElement =
    document.getElementById("riskTitle");

const criticalCountElement =
    document.getElementById("criticalCount");

const highCountElement =
    document.getElementById("highCount");

const mediumCountElement =
    document.getElementById("mediumCount");

const filesCountElement =
    document.getElementById("filesCount");

const totalFindingsElement =
    document.getElementById("totalFindings");

const findingBadgeElement =
    document.getElementById("findingBadge");

const findingsListElement =
    document.getElementById("findingsList");

const legendCritical =
    document.getElementById("legendCritical");

const legendHigh =
    document.getElementById("legendHigh");

const legendMedium =
    document.getElementById("legendMedium");

const legendLow =
    document.getElementById("legendLow");

const lastScanElement =
    document.getElementById("lastScan");

const scanDurationElement =
    document.getElementById("scanDuration");

const donutElement =
    document.querySelector(".donut");

const scanModal =
    document.getElementById("scanModal");

const scanProgressBar =
    document.getElementById("scanProgressBar");

const scanMessage =
    document.getElementById("scanMessage");
const findingModal =
    document.getElementById("findingModal");

const modalFindingTitle =
    document.getElementById("modalFindingTitle");

const modalSeverity =
    document.getElementById("modalSeverity");

const modalFile =
    document.getElementById("modalFile");

const modalLine =
    document.getElementById("modalLine");

const modalValue =
    document.getElementById("modalValue");

const modalDescription =
    document.getElementById("modalDescription");

const modalRemediation =
    document.getElementById("modalRemediation");


// ======================================================
// UPLOAD PROJECT ZIP
// ======================================================

async function uploadProject() {

    const file =
        projectZipInput?.files?.[0];

    if (!file) {

        alert(
            "Please select a ZIP file first."
        );

        return;

    }


    if (
        !file.name
            .toLowerCase()
            .endsWith(".zip")
    ) {

        alert(
            "Only ZIP project files are supported."
        );

        return;

    }


    // Backend maximum upload size: 25 MB
    const maxUploadSize =
        25 * 1024 * 1024;

    if (file.size > maxUploadSize) {

        alert(
            "The ZIP file exceeds the 25 MB upload limit."
        );

        return;

    }


    const projectName =
        file.name
            .replace(/\.zip$/i, "")
            .trim() ||
        "uploaded_project";


    try {

        showScanModal();

        setScanButtonsDisabled(true);

        const startTime =
            performance.now();


        const response =
            await fetch(
                `${API_BASE}/api/upload-project?project=${encodeURIComponent(projectName)}`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/zip"
                    },

                    body: file
                }
            );


        if (!response.ok) {

            throw new Error(
                `Server returned ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                data.error ||
                "Project upload failed"
            );

        }


        const duration =
            (
                (performance.now() - startTime)
                / 1000
            ).toFixed(2);


        updateDashboard(
            data,
            duration
        );

        await loadScanHistory(projectName);

        await loadSecurityAnalytics();


        completeScanModal();


        // Reset the file input after success
        projectZipInput.value = "";


        console.log(
            "SecuVanta project upload completed successfully",
            data
        );

    } catch (error) {

        console.error(
            "Project upload failed:",
            error
        );


        hideScanModal();


        alert(
            "Project upload failed: " +
            error.message
        );

    } finally {

        setScanButtonsDisabled(false);

    }

}
// ======================================================
// UPDATE DASHBOARD
// ======================================================

function updateDashboard(
    data,
    duration
) {

    const summary =
        data.summary;

    const severity =
        summary.severity_summary;
    const activeFindingBreakdown =
    document.getElementById(
        "activeFindingBreakdown"
    );


if (activeFindingBreakdown) {

    const critical =
        severity.CRITICAL || 0;

    const high =
        severity.HIGH || 0;

    const medium =
        severity.MEDIUM || 0;

    const low =
        severity.LOW || 0;


    const parts = [];


    if (critical > 0) {

        parts.push(
            `${critical} CRITICAL`
        );

    }

    if (high > 0) {

        parts.push(
            `${high} HIGH`
        );

    }

    if (medium > 0) {

        parts.push(
            `${medium} MEDIUM`
        );

    }

    if (low > 0) {

        parts.push(
            `${low} LOW`
        );

    }


    activeFindingBreakdown.textContent =
        parts.length
            ? parts.join(" · ")
            : "NO ACTIVE THREATS";

}


    // Save findings for filtering

    currentFindings =
        data.findings || [];


    // --------------------------------------------------
    // Risk Score
    // --------------------------------------------------

    const riskScore =
        summary.risk_score || 0;


    if (riskScoreElement) {

        animateNumber(
            riskScoreElement,
            riskScore
        );

    }


    // --------------------------------------------------
    // Security Score
    // --------------------------------------------------

    const securityScore =
        Math.max(
            0,
            100 - riskScore
        );
        // --------------------------------------------------
// Security Score State
// --------------------------------------------------

const securityScoreState =
    document.getElementById(
        "securityScoreState"
    );

const securityScoreStateDot =
    document.getElementById(
        "securityScoreStateDot"
    );


if (securityScoreState) {

    if (riskScore === 0) {

        securityScoreState.textContent =
            "SECURE";

    }

    else if (riskScore < 20) {

        securityScoreState.textContent =
            "LOW RISK";

    }

    else if (riskScore < 50) {

        securityScoreState.textContent =
            "MODERATE RISK";

    }

    else if (riskScore < 80) {

        securityScoreState.textContent =
            "HIGH RISK";

    }

    else {

        securityScoreState.textContent =
            "AT RISK";

    }

}


if (securityScoreStateDot) {

    securityScoreStateDot.classList.toggle(
        "secure",
        riskScore === 0
    );

}


    if (securityScoreElement) {

        animateNumber(
            securityScoreElement,
            securityScore
        );

    }


    if (securityProgressElement) {

        securityProgressElement.style.width =
            `${securityScore}%`;

    }


    // --------------------------------------------------
    // Risk Title
    // --------------------------------------------------

    updateRiskTitle(
        summary.risk_level
    );


    // --------------------------------------------------
    // Severity Counts
    // --------------------------------------------------

    updateText(
        criticalCountElement,
        severity.CRITICAL || 0
    );


    updateText(
        highCountElement,
        severity.HIGH || 0
    );


    updateText(
        mediumCountElement,
        severity.MEDIUM || 0
    );


    // --------------------------------------------------
    // Files Scanned
    // --------------------------------------------------

    updateText(
        filesCountElement,
        summary.files_scanned || 0
    );


    // --------------------------------------------------
    // Total Findings
    // --------------------------------------------------

    updateText(
        totalFindingsElement,
        summary.total_findings || 0
    );


    // Sidebar Badge

    updateText(
        findingBadgeElement,
        summary.total_findings || 0
    );


    // --------------------------------------------------
    // Legend
    // --------------------------------------------------

    updateText(
        legendCritical,
        severity.CRITICAL || 0
    );


    updateText(
        legendHigh,
        severity.HIGH || 0
    );


    updateText(
        legendMedium,
        severity.MEDIUM || 0
    );


    updateText(
        legendLow,
        severity.LOW || 0
    );


    // --------------------------------------------------
    // Donut Chart
    // --------------------------------------------------

    updateDonutChart(
        severity,
        summary.total_findings
    );


    // --------------------------------------------------
    // Scan Information
    // --------------------------------------------------

    if (lastScanElement) {

        lastScanElement.textContent =
            "Just now";

    }


    if (scanDurationElement) {

        scanDurationElement.textContent =
            `${duration}s`;

    }


    // --------------------------------------------------
    // Findings
    // --------------------------------------------------

    renderFindings(
        currentFindings
    );
    // --------------------------------------------------
// Security Change Intelligence
// --------------------------------------------------

renderScanComparison(
    data,
    "mainScanComparison"
);


    console.log(
        "Dashboard updated successfully"
    );

}


// ======================================================
// UPDATE RISK TITLE
// ======================================================

function updateRiskTitle(level) {

    if (!riskTitleElement) return;


    if (level === "SAFE") {

        riskTitleElement.textContent =
            "SYSTEM SECURE";

        riskTitleElement.style.color =
            "#63e6be";

        return;

    }


    riskTitleElement.textContent =
        `${level} RISK DETECTED`;


    const colors = {

        CRITICAL: "#ff5470",

        HIGH: "#ff7b5c",

        MEDIUM: "#f5c45e",

        LOW: "#63e6be"

    };


    riskTitleElement.style.color =
        colors[level] || "#ffffff";

}


// ======================================================
// UPDATE DONUT CHART
// ======================================================

function updateDonutChart(
    severity,
    total
) {

    if (!donutElement) return;


    const donutTotalFindingsElement =
        document.getElementById(
            "donutTotalFindings"
        );


    if (donutTotalFindingsElement) {

        donutTotalFindingsElement.textContent =
            total || 0;

    }


    if (!total || total === 0) {

        donutElement.style.background =
            "conic-gradient(#63e6be 0deg 360deg)";

        return;

    }


    const critical =
        severity.CRITICAL || 0;

    const high =
        severity.HIGH || 0;

    const medium =
        severity.MEDIUM || 0;

    const low =
        severity.LOW || 0;


    const criticalPercent =
        (critical / total) * 100;

    const highPercent =
        (high / total) * 100;

    const mediumPercent =
        (medium / total) * 100;

    const lowPercent =
        (low / total) * 100;


    const criticalEnd =
        criticalPercent;

    const highEnd =
        criticalEnd + highPercent;

    const mediumEnd =
        highEnd + mediumPercent;

    const lowEnd =
        mediumEnd + lowPercent;


    donutElement.style.background = `
        conic-gradient(
            #ff5470 0% ${criticalEnd}%,
            #ff7b5c ${criticalEnd}% ${highEnd}%,
            #f5c45e ${highEnd}% ${mediumEnd}%,
            #63e6be ${mediumEnd}% ${lowEnd}%
        )
    `;

}


// ======================================================
// RENDER FINDINGS
// ======================================================

function renderFindings(findings) {

    if (!findingsListElement) return;


    findingsListElement.innerHTML = "";


    let filteredFindings =
        findings;


    if (currentFilter !== "ALL") {

        filteredFindings =
            findings.filter(
                finding =>
                    finding.severity ===
                    currentFilter
            );

    }


    if (
        !filteredFindings ||
        filteredFindings.length === 0
    ) {

        findingsListElement.innerHTML = `

            <div class="empty-state">

                🛡 No security threats detected

            </div>

        `;

        return;

    }


    filteredFindings.forEach(
        finding => {

            const findingRow =
                document.createElement("div");


            findingRow.className =
                "finding-row";


            const severity =
                finding.severity.toLowerCase();


            findingRow.innerHTML = `

                <span>

                    <span class="severity-badge ${severity}">
                        ${escapeHtml(finding.severity)}
                    </span>

                </span>


                <span class="threat-name">
                    ${escapeHtml(finding.finding_type)}
                </span>


                <span class="location">
                    ${escapeHtml(
                        formatLocation(
                            finding.file_path,
                            finding.line_number
                        )
                    )}
                </span>


                <span class="status-open">
    ● ${escapeHtml(
        (
            finding.lifecycle ||
            finding.status ||
            "OPEN"
        ).toUpperCase()
    )}
</span>

            `;


            findingRow.addEventListener(
                "click",
                () => openFindingModal(finding)
            );

            findingsListElement.appendChild(
                findingRow
            );

        }
    );

}


// ======================================================
// FILTER FINDINGS
// ======================================================

function filterFindings(filter) {

    currentFilter =
        filter;


    document
        .querySelectorAll(".filter")
        .forEach(button => {

            button.classList.remove(
                "active"
            );

        });


    const buttons =
        document.querySelectorAll(
            ".filter"
        );


    buttons.forEach(button => {

        if (
            button.textContent
                .trim()
                .toUpperCase() ===
            filter
        ) {

            button.classList.add(
                "active"
            );

        }

    });


    renderFindings(
        currentFindings
    );

}


// ======================================================
// FORMAT LOCATION
// ======================================================

function formatLocation(
    path,
    lineNumber
) {

    if (!path) {

        return `Unknown : Line ${lineNumber}`;

    }


    const normalized =
        path.replace(/\\/g, "/");


    const parts =
        normalized.split("/");


    const fileName =
        parts.slice(-2).join("/");


    return `${fileName} : Line ${lineNumber}`;

}


// ======================================================
// UPDATE TEXT
// ======================================================

function updateText(
    element,
    value
) {

    if (element) {

        element.textContent =
            value;

    }

}


// ======================================================
// ANIMATE NUMBERS
// ======================================================

function animateNumber(
    element,
    target
) {

    const duration = 500;

    const start =
        Number(element.textContent) || 0;

    const difference =
        target - start;

    const startTime =
        performance.now();


    function update(currentTime) {

        const progress =
            Math.min(
                (currentTime - startTime) /
                duration,
                1
            );


        const value =
            Math.round(
                start +
                difference * progress
            );


        element.textContent =
            value;


        if (progress < 1) {

            requestAnimationFrame(
                update
            );

        }

    }


    requestAnimationFrame(
        update
    );

}


// ======================================================
// SCAN MODAL
// ======================================================

function showScanModal() {

    if (!scanModal) return;


    scanModal.classList.add(
        "show"
    );


    if (scanMessage) {

        scanMessage.textContent =
            "SecuVanta is analyzing your project...";

    }


    if (scanProgressBar) {

        scanProgressBar.style.width =
            "20%";


        setTimeout(() => {

            scanProgressBar.style.width =
                "65%";

        }, 200);

    }

}


function completeScanModal() {

    if (scanProgressBar) {

        scanProgressBar.style.width =
            "100%";

    }


    if (scanMessage) {

        scanMessage.textContent =
            "Scan completed successfully.";

    }


    setTimeout(
        hideScanModal,
        700
    );

}


function hideScanModal() {

    if (!scanModal) return;


    scanModal.classList.remove(
        "show"
    );


    if (scanProgressBar) {

        scanProgressBar.style.width =
            "0%";

    }

}


// ======================================================
// BUTTON STATE
// ======================================================

function setScanButtonsDisabled(disabled) {

    const buttons =
        document.querySelectorAll(
            ".scan-button, .scan-control button"
        );


    buttons.forEach(button => {

        button.disabled =
            disabled;

    });

}


// ======================================================
// SAFE HTML
// ======================================================

function escapeHtml(value) {

    const div =
        document.createElement("div");


    div.textContent =
        value || "";
    return div.innerHTML;

}

// ======================================================
// INITIALIZE DASHBOARD
// ======================================================

window.addEventListener("DOMContentLoaded", () => {

    console.log(
        "SecuVanta Dashboard Loaded"
    );

    loadScanHistory();

    loadSecurityAnalytics();

    startLivePolling();
});
// ======================================================
// FINDING REMEDIATION ENGINE
// ======================================================

function getRemediation(findingType) {

    const remediation = {

        "AWS Access Key":
            "Immediately revoke or rotate the exposed AWS access key. " +
            "Move credentials to environment variables or AWS IAM roles. " +
            "Never commit AWS credentials to source control.",


        "Hardcoded Password":
            "Remove the password from the source code. Store it in an " +
            "environment variable or a dedicated secrets manager. " +
            "Rotate the exposed password if it has already been used.",


        "Database Connection String":
            "Remove the database connection string from the source code. " +
            "Store it securely using environment variables or a secrets " +
            "management service.",


        "GitHub Personal Access Token":
            "Immediately revoke the exposed GitHub token and generate a new one. " +
            "Store tokens in environment variables or GitHub Secrets.",


        "JWT Token":
            "Do not hardcode JWT tokens in source files. Generate tokens dynamically " +
            "and store signing secrets securely.",


        "Private Key":
            "Remove the private key from the repository immediately. Rotate the key " +
            "and use a secure key management system.",


        "Bearer Token":
            "Revoke the exposed bearer token if possible. Store authentication tokens " +
            "outside the source code using environment variables or secure storage.",


        "High-Entropy Secret":
            "Review this value to determine whether it is a credential, token, or API key. " +
            "If sensitive, remove it from source control and store it securely."

    };


    return remediation[findingType] ||

        "Review this security finding and remove sensitive information from " +
        "the source code. Store credentials and secrets using a secure secrets " +
        "management solution.";

}
// ======================================================
// OPEN FINDING MODAL
// ======================================================
// ======================================================
// RENDER INTELLIGENCE REASONS
// ======================================================

function renderIntelligenceReasons(
    listId,
    countId,
    reasons
) {

    const list =
        document.getElementById(
            listId
        );

    const count =
        document.getElementById(
            countId
        );


    const safeReasons =
        Array.isArray(reasons)
            ? reasons.filter(
                reason =>
                    typeof reason === "string" &&
                    reason.trim().length > 0
            )
            : [];


    if (count) {

        count.textContent =
            `${safeReasons.length} signal${
                safeReasons.length === 1
                    ? ""
                    : "s"
            }`;
    }


    if (!list) return;


    list.innerHTML = "";


    if (safeReasons.length === 0) {

        const item =
            document.createElement(
                "li"
            );

        item.textContent =
            "No evidence available.";

        list.appendChild(item);

        return;
    }


    safeReasons.forEach(
        reason => {

            const item =
                document.createElement(
                    "li"
                );


            const icon =
                document.createElement(
                    "span"
                );

            icon.className =
                "intelligence-reason-icon";

            icon.textContent =
                "✓";


            const text =
                document.createElement(
                    "span"
                );

            text.textContent =
                reason;


            item.appendChild(icon);

            item.appendChild(text);

            list.appendChild(item);
        }
    );
}
function openFindingModal(finding) {

    if (!findingModal) return;


    // ======================================================
    // BASIC FINDING INFORMATION
    // ======================================================

    modalFindingTitle.textContent =
        finding.finding_type ||
        "Security Finding";


    modalSeverity.textContent =
        finding.severity ||
        "UNKNOWN";


    modalSeverity.className =
        `severity-badge ${
            (finding.severity || "")
                .toLowerCase()
        }`;


    modalFile.textContent =
        finding.file_path ||
        "Unknown";


    modalLine.textContent =
        `Line ${
            finding.line_number ||
            "Unknown"
        }`;


    modalValue.textContent =
        finding.value ||
        "No value available";


    modalDescription.textContent =
        finding.description ||
        "No description available.";


    modalRemediation.textContent =
        getRemediation(
            finding.finding_type
        );


    // ======================================================
    // STATUS
    // ======================================================

    const modalStatus =
        document.getElementById(
            "modalStatus"
        );


    if (modalStatus) {

        const status =
            (
                finding.status ||
                "OPEN"
            ).toUpperCase();

        const lifecycle =
            (
                finding.lifecycle ||
                ""
            ).toUpperCase();


        if (lifecycle && lifecycle !== "NEW") {

            modalStatus.textContent =
                `● ${status} · ${lifecycle}`;

        } else {

            modalStatus.textContent =
                `● ${status}`;
        }

    }


    // ======================================================
    // SECURITY INTELLIGENCE
    // ======================================================

    const riskContribution =
        document.getElementById(
            "modalRiskContribution"
        );

    if (riskContribution) {

        riskContribution.textContent =
            finding.risk_contribution !== undefined
                ? Number(
                    finding.risk_contribution
                ).toFixed(2)
                : "—";
    }


    const confidence =
        document.getElementById(
            "modalConfidence"
        );

    if (confidence) {

        confidence.textContent =
            finding.confidence ||
            "—";
    }


    const confidenceScore =
        document.getElementById(
            "modalConfidenceScore"
        );

    if (confidenceScore) {

        confidenceScore.textContent =
            finding.confidence_score !== undefined
                ? `${finding.confidence_score}% confidence`
                : "—";
    }


    const exposure =
        document.getElementById(
            "modalExposure"
        );

    if (exposure) {

        exposure.textContent =
            finding.exposure ||
            "—";
    }


    const falsePositive =
        document.getElementById(
            "modalFalsePositive"
        );

    if (falsePositive) {

        falsePositive.textContent =
            finding.false_positive_risk ||
            "—";
    }


    // ======================================================
    // LIFECYCLE
    // ======================================================

    const lifecycleElement =
        document.getElementById(
            "modalLifecycle"
        );

    if (lifecycleElement) {

        lifecycleElement.textContent =
            (
                finding.lifecycle ||
                "NEW"
            ).toUpperCase();
    }


    const timesSeenElement =
        document.getElementById(
            "modalTimesSeen"
        );

    if (timesSeenElement) {

        const timesSeen =
            Number(
                finding.times_seen || 1
            );

        timesSeenElement.textContent =
            `${timesSeen} scan${
                timesSeen === 1
                    ? ""
                    : "s"
            }`;
    }


    // ======================================================
    // VARIABLE + EXPOSURE SCORE
    // ======================================================

    const variableElement =
        document.getElementById(
            "modalVariableName"
        );

    if (variableElement) {

        variableElement.textContent =
            finding.variable_name ||
            "Not identified";
    }


    const exposureScoreElement =
        document.getElementById(
            "modalExposureScore"
        );

    if (exposureScoreElement) {

        exposureScoreElement.textContent =
            finding.exposure_score !== undefined
                ? `${finding.exposure_score}/100 exposure`
                : "Exposure score unavailable";
    }


    // ======================================================
    // CONTEXT REASONS
    // ======================================================

    renderIntelligenceReasons(
        "modalContextReasons",
        "modalContextCount",
        finding.context_reasons || []
    );


    // ======================================================
    // RISK REASONS
    // ======================================================

    renderIntelligenceReasons(
        "modalRiskReasons",
        "modalRiskReasonCount",
        finding.risk_reasons || []
    );


    // ======================================================
    // OPEN MODAL
    // ======================================================

    findingModal.classList.add(
        "show"
    );


    document.documentElement.style.overflow =
        "hidden";

    document.body.style.overflow =
        "hidden";


    // ======================================================
    // RESET SCROLL
    // ======================================================

    const modalContent =
        findingModal.querySelector(
            ".finding-modal-content"
        );


    if (modalContent) {

        modalContent.scrollTop = 0;
    }
}
// ======================================================
// CLOSE FINDING MODAL
// ======================================================

function closeFindingModal() {

    if (!findingModal) return;


    findingModal.classList.remove("show");


    document.documentElement.style.overflow = "";

    document.body.style.overflow = "";

}
// ======================================================
// ESCAPE KEY - CLOSE FINDING MODAL
// ======================================================

document.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Escape" &&
            findingModal &&
            findingModal.classList.contains("show")
        ) {

            closeFindingModal();

        }

    }
);
// ======================================================
// LOAD SCAN HISTORY
// ======================================================

async function loadScanHistory(projectId = null) {

    try {

        const historyUrl = projectId
            ? `${API_BASE}/api/history?project=${encodeURIComponent(projectId)}`
            : `${API_BASE}/api/history`;

        const response = await fetch(
            historyUrl
        );

        if (!response.ok) {

            throw new Error(
                `History server returned ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                "Failed to load scan history"
            );

        }


        scanHistory =
            data.history || [];

        if (scanHistory.length > 0) {
    const latestScan =
        [...scanHistory].sort(
            (a, b) =>
                new Date(b.scan_time) -
                new Date(a.scan_time)
        )[0];

    updateRiskTitle(
        latestScan.risk_level || "SAFE"
    );
}
        renderScanHistory(
            scanHistory
        );


        updateHistorySummary(
            scanHistory
        );


        console.log(
            "Scan history loaded successfully",
            scanHistory
        );

    } catch (error) {

        console.error(
            "Failed to load scan history:",
            error
        );

        renderHistoryError();

    }

}
// ======================================================
// LOAD SECURITY ANALYTICS
// ======================================================

async function loadSecurityAnalytics() {

    try {

        const response = await fetch(
            `${API_BASE}/api/analytics?ts=${Date.now()}`,
            {
                cache: "no-store"
            }
        );


        if (!response.ok) {

            throw new Error(
                `Analytics server returned ${response.status}`
            );

        }


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                data.error ||
                "Failed to load security analytics"
            );

        }


        const analytics =
            data.analytics ||
            {};
        const securityPosture =
    data.security_posture ||
    {};


        updateText(
            document.getElementById(
                "totalScans"
            ),
            analytics.total_scans ?? 0
        );


        updateText(
            document.getElementById(
                "averageRisk"
            ),
            analytics.average_risk ?? 0
        );


        updateText(
            document.getElementById(
                "highestRisk"
            ),
            analytics.highest_risk ?? 0
        );


        updateText(
            document.getElementById(
                "analyticsFindings"
            ),
            analytics.total_findings ?? 0
        );


        updateText(
            document.getElementById(
                "latestHistoryRisk"
            ),
            analytics.latest_risk ?? 0
        );


        const riskTrendElement =
            document.getElementById(
                "riskTrend"
            );


        if (riskTrendElement) {

            const trend =
                analytics.risk_trend ||
                "NO_DATA";


            const change =
                Number(
                    analytics.risk_change
                ) || 0;


            if (trend === "INCREASED") {

                riskTrendElement.textContent =
                    `↑ ${Math.abs(change)}`;

            }

            else if (
                trend === "DECREASED"
            ) {

                riskTrendElement.textContent =
                    `↓ ${Math.abs(change)}`;

            }

            else if (
                trend === "STABLE"
            ) {

                riskTrendElement.textContent =
                    "STABLE";

            }

            else {

                riskTrendElement.textContent =
                    "—";

            }

        }
// ======================================================
// SECURITY POSTURE
// ======================================================

const postureScore =
    securityPosture.posture_score ?? 0;

const postureState =
    securityPosture.posture ||
    "NO_DATA";
    // ======================================================
// POSTURE VISUAL STATE
// ======================================================

const postureCard =
    document.querySelector(
        ".posture-card"
    );

const postureBadge =
    document.getElementById(
        "postureBadge"
    );


if (postureCard) {

    postureCard.classList.remove(
        "posture-good",
        "posture-warning",
        "posture-poor"
    );


    if (postureState === "GOOD") {

        postureCard.classList.add(
            "posture-good"
        );

    }

    else if (
        postureState === "NEEDS_ATTENTION"
    ) {

        postureCard.classList.add(
            "posture-warning"
        );

    }

    else if (
        postureState === "POOR"
    ) {

        postureCard.classList.add(
            "posture-poor"
        );

    }

}


if (postureBadge) {

    postureBadge.classList.remove(
        "posture-good",
        "posture-warning",
        "posture-poor"
    );


    if (postureState === "GOOD") {

        postureBadge.classList.add(
            "posture-good"
        );

    }

    else if (
        postureState === "NEEDS_ATTENTION"
    ) {

        postureBadge.classList.add(
            "posture-warning"
        );

    }

    else if (
        postureState === "POOR"
    ) {

        postureBadge.classList.add(
            "posture-poor"
        );

    }

}

const postureTrend =
    securityPosture.posture_trend ||
    "NO_DATA";


// ------------------------------------------------------
// SCORE
// ------------------------------------------------------

updateText(
    document.getElementById(
        "postureScore"
    ),
    postureScore
);
// ------------------------------------------------------
// POSTURE PROGRESS
// ------------------------------------------------------

const postureProgress =
    document.getElementById(
        "postureProgressFill"
    );

if (postureProgress) {

    const safeScore =
        Math.max(
            0,
            Math.min(
                100,
                Number(postureScore) || 0
            )
        );

    postureProgress.style.width =
        `${safeScore}%`;

}


// ------------------------------------------------------
// STATE
// ------------------------------------------------------

updateText(
    document.getElementById(
        "postureState"
    ),
    postureState.replace(
        "_",
        " "
    )
);


// ------------------------------------------------------
// TREND
// ------------------------------------------------------

let postureTrendText = "—";


if (postureTrend === "IMPROVING") {

    postureTrendText =
        "↓ IMPROVING";

}

else if (postureTrend === "WORSENING") {

    postureTrendText =
        "↑ WORSENING";

}

else if (postureTrend === "STABLE") {

    postureTrendText =
        "STABLE";

}

else if (
    postureTrend === "NO_COMPARISON"
) {

    postureTrendText =
        "NO COMPARISON";

}


updateText(
    document.getElementById(
        "postureTrend"
    ),
    postureTrendText
);


// ------------------------------------------------------
// BADGE
// ------------------------------------------------------

updateText(
    document.getElementById(
        "postureBadge"
    ),
    postureState.replace(
        "_",
        " "
    )
);


// ------------------------------------------------------
// LIFECYCLE METRICS
// ------------------------------------------------------

updateText(
    document.getElementById(
        "postureNew"
    ),
    securityPosture.new_findings ?? 0
);


updateText(
    document.getElementById(
        "posturePersistent"
    ),
    securityPosture.persistent_findings ?? 0
);


updateText(
    document.getElementById(
        "postureReappeared"
    ),
    securityPosture.reappeared_findings ?? 0
);


updateText(
    document.getElementById(
        "postureResolved"
    ),
    securityPosture.resolved_findings ?? 0
);


// ------------------------------------------------------
// EXPLANATION
// ------------------------------------------------------

updateText(
    document.getElementById(
        "postureExplanation"
    ),
    securityPosture.explanation ||
        "Security posture information is unavailable."
);

        console.log(
            "Security analytics loaded successfully",
            analytics
        );

    } catch (error) {

        console.error(
            "Failed to load security analytics:",
            error
        );

    }

}
// ======================================================
// FORMAT HISTORY TIME
// ======================================================

function formatHistoryTime(scanTime) {

    if (!scanTime) {

        return "Unknown time";

    }

    const date = new Date(scanTime);

    if (isNaN(date.getTime())) {

        return scanTime;

    }

    const now = new Date();

    const difference = now - date;

    const seconds = Math.floor(
        difference / 1000
    );

    const minutes = Math.floor(
        seconds / 60
    );

    const hours = Math.floor(
        minutes / 60
    );

    const days = Math.floor(
        hours / 24
    );

    if (seconds < 60) {

        return "Just now";

    }

    if (minutes < 60) {

        return `${minutes} minute${
            minutes !== 1 ? "s" : ""
        } ago`;

    }

    if (hours < 24) {

        return `${hours} hour${
            hours !== 1 ? "s" : ""
        } ago`;

    }

    if (days < 7) {

        return `${days} day${
            days !== 1 ? "s" : ""
        } ago`;

    }

    return date.toLocaleDateString(
        undefined,
        {
            day: "numeric",
            month: "short",
            year: "numeric"
        }
    );

}
// ======================================================
// RENDER SCAN HISTORY
// ======================================================

function renderScanHistory(history) {

    const historyList =
        document.getElementById(
            "historyList"
        );


    if (!historyList) return;


    historyList.innerHTML = "";


    if (
        !history ||
        history.length === 0
    ) {

        historyList.innerHTML = `

            <div class="history-empty">

                <div class="history-empty-icon">
                    🛡
                </div>

                <h3>No Scan History Yet</h3>

                <p>
                    Run your first security scan to start
                    building your security timeline.
                </p>

            </div>

        `;

        return;

    }


    history.forEach(
        (scan, index) => {

            const historyItem =
                document.createElement("div");


            historyItem.className =
                "history-item";


            const riskLevel =
                scan.risk_level || "SAFE";


            const riskClass =
                riskLevel.toLowerCase();


            const severity =
                scan.severity_summary || {};


            historyItem.innerHTML = `

                <div class="history-main">

                    <div class="history-number">

                        ${String(index + 1).padStart(2, "0")}

                    </div>


                    <div class="history-project">

                        <div class="history-project-name">

                            ${escapeHtml(
    scan.project_id ||
    scan.target ||
    "Unknown Project"
)}

                        </div>


                        <div class="history-time">

                            ${formatHistoryTime(
                                scan.scan_time
                            )}

                        </div>

                    </div>

                </div>


                <div class="history-findings">

                    <div class="history-findings-number">

                        ${scan.total_findings || 0}

                    </div>

                    <div class="history-label">

                        Findings

                    </div>

                </div>


                <div class="history-severity-summary">

                    <span class="history-critical">
                        ${severity.CRITICAL || 0} C
                    </span>

                    <span class="history-high">
                        ${severity.HIGH || 0} H
                    </span>

                    <span class="history-medium">
                        ${severity.MEDIUM || 0} M
                    </span>

                </div>


                <div class="history-risk">

                    <div class="history-score ${riskClass}">

                        ${scan.risk_score || 0}

                    </div>

                    <div class="history-risk-level ${riskClass}">

                        ${escapeHtml(riskLevel)}

                    </div>

                </div>


                <div class="history-duration">

                    ${(scan.scan_duration || 0).toFixed(3)}s

                </div>


                <div class="history-arrow">

                    →

                </div>

            `;


            historyItem.addEventListener(
    "click",
    () => openHistoryDetails(scan)
);


            historyList.appendChild(
                historyItem
            );

        }
    );

}
// ======================================================
// UPDATE HISTORY SUMMARY
// ======================================================

// ======================================================
// UPDATE HISTORY SUMMARY
// ======================================================

function updateHistorySummary(history) {

    loadSecurityAnalytics();

}
// ======================================================
// HISTORY ERROR
// ======================================================

function renderHistoryError() {

    const historyList =
        document.getElementById(
            "historyList"
        );


    if (!historyList) return;


    historyList.innerHTML = `

        <div class="history-empty">

            <div class="history-empty-icon">
                ⚠
            </div>

            <h3>Unable to Load History</h3>

            <p>
                Check that the SecuVanta server is running.
            </p>

        </div>

    `;

}
// ======================================================
// OPEN HISTORY SCAN
// ======================================================

function openHistoryScan(scan) {

    console.log(
        "Selected historical scan:",
        scan
    );


    alert(

        `SCAN DETAILS\n\n` +

        `Project: ${scan.target}\n` +

        `Risk Score: ${scan.risk_score}/100\n` +

        `Risk Level: ${scan.risk_level}\n` +

        `Findings: ${scan.total_findings}\n` +

        `Files Scanned: ${scan.files_scanned}\n` +

        `Duration: ${scan.scan_duration}s`

    );

}

// ======================================================
// FINDING MODAL EVENTS
// ======================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        const closeFindingModalButton =
            document.getElementById(
                "closeFindingModal"
            );


        if (closeFindingModalButton) {

            closeFindingModalButton.addEventListener(
                "click",
                closeFindingModal
            );

        }


        if (findingModal) {

            findingModal.addEventListener(
                "click",
                event => {

                    if (
                        event.target === findingModal
                    ) {

                        closeFindingModal();

                    }

                }
            );

        }

    }
);
// ======================================================
// SCAN COMPARISON INTELLIGENCE
// ======================================================

function compareScans(currentScan, previousScan) {

    // No previous scan available

    if (!previousScan) {

        return {

            available: false,

        };

    }


    const currentFindings =
        currentScan.findings || [];

    const previousFindings =
        previousScan.findings || [];


    // If detailed findings are unavailable,
    // we can still compare summary information

    const currentRisk =
        currentScan.risk_score || 0;

    const previousRisk =
        previousScan.risk_score || 0;


    const riskDifference =
        currentRisk - previousRisk;


    // --------------------------------------------------
    // CREATE FINDING IDENTIFIERS
    // --------------------------------------------------

    function getFindingId(finding) {

    // SecuVanta backend identity
    if (finding.fingerprint) {
        return finding.fingerprint;
    }


    // Legacy fallback for older history records
    return [
        finding.finding_type,
        finding.file_path,
        finding.line_number
    ].join("|");
}


    const currentFindingIds =
        new Set(
            currentFindings.map(getFindingId)
        );


    const previousFindingIds =
        new Set(
            previousFindings.map(getFindingId)
        );


    // --------------------------------------------------
    // NEW FINDINGS
    // --------------------------------------------------

    const newFindings =
        currentFindings.filter(
            finding =>
                !previousFindingIds.has(
                    getFindingId(finding)
                )
        );


    // --------------------------------------------------
    // RESOLVED FINDINGS
    // --------------------------------------------------

    const resolvedFindings =
        previousFindings.filter(
            finding =>
                !currentFindingIds.has(
                    getFindingId(finding)
                )
        );


    // --------------------------------------------------
    // PERSISTENT FINDINGS
    // --------------------------------------------------

    const persistentFindings =
        currentFindings.filter(
            finding =>
                previousFindingIds.has(
                    getFindingId(finding)
                )
        );


    return {

        available: true,

        currentRisk,

        previousRisk,

        riskDifference,

        newFindings,

        resolvedFindings,

        persistentFindings,

        currentTotal:
            currentScan.total_findings || 0,

        previousTotal:
            previousScan.total_findings || 0,

        comparisonPossible:

            currentFindings.length > 0 &&

            previousFindings.length > 0,

    };

}
// ======================================================
// OPEN HISTORICAL SCAN DETAILS
// ======================================================

function openHistoryDetails(scan) {
    

    const modal = document.getElementById(
        "historyDetailsModal"
    );


    if (!modal || !scan) {

        return;

    }


    // Basic information

    document.getElementById(
        "historyModalRiskScore"
    ).textContent =

        scan.risk_score ?? 0;


    document.getElementById(
        "historyModalRiskLevel"
    ).textContent =

        `${scan.risk_level || "SAFE"} RISK`;


    document.getElementById(
        "historyModalFindings"
    ).textContent =

        scan.total_findings ?? 0;


    document.getElementById(
        "historyModalFiles"
    ).textContent =

        scan.files_scanned ?? 0;


    document.getElementById(
        "historyModalDuration"
    ).textContent =

        `${Number(
            scan.scan_duration || 0
        ).toFixed(3)}s`;


    document.getElementById(
    "historyModalTarget"
).textContent =
    scan.project_id ||
    scan.target ||
    "Unknown";

    document.getElementById(
        "historyModalScanId"
    ).textContent =

        scan.scan_id || "Unknown";


    // Format exact scan time

    const date = new Date(scan.scan_time);


    document.getElementById(
        "historyModalTime"
    ).textContent =

        isNaN(date.getTime())

            ? "Unknown"

            : date.toLocaleString();


    // Severity breakdown

    const severity =

        scan.severity_summary || {};


    document.getElementById(
        "historyCritical"
    ).textContent =

        severity.CRITICAL || 0;


    document.getElementById(
        "historyHigh"
    ).textContent =

        severity.HIGH || 0;


    document.getElementById(
        "historyMedium"
    ).textContent =

        severity.MEDIUM || 0;


    document.getElementById(
        "historyLow"
    ).textContent =

        severity.LOW || 0;


    // Dynamic risk color

    const riskLevelElement = document.getElementById(
        "historyModalRiskLevel"
    );


    const riskScoreElement = document.getElementById(
        "historyModalRiskScore"
    );


    const level =

        (scan.risk_level || "")
            .toUpperCase();


    let riskColor = "#5ee6a8";


    if (level === "CRITICAL") {

        riskColor = "#ff5d73";

    }

    else if (level === "HIGH") {

        riskColor = "#ff8a65";

    }

    else if (level === "MEDIUM") {

        riskColor = "#ffd166";

    }


    riskLevelElement.style.color = riskColor;

    riskScoreElement.style.color = riskColor;
    // ======================================================
// SCAN COMPARISON
// ======================================================

renderScanComparison(scan);
    // ======================================================
// HISTORICAL FINDINGS
// ======================================================

renderHistoryFindings(
    scan.findings || []
);

    // Open modal

    modal.classList.add("active");

}
// ======================================================
// HISTORY MODAL CONTROLS
// ======================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        const modal = document.getElementById(
            "historyDetailsModal"
        );


        const closeButton = document.getElementById(
            "closeHistoryDetails"
        );


        const footerCloseButton = document.getElementById(
            "historyModalCloseButton"
        );


        const backdrop = document.querySelector(
            ".history-modal-backdrop"
        );


        function closeHistoryModal() {

            if (modal) {

                modal.classList.remove(
                    "active"
                );

            }

        }


        if (closeButton) {

            closeButton.addEventListener(
                "click",
                closeHistoryModal
            );

        }


        if (footerCloseButton) {

            footerCloseButton.addEventListener(
                "click",
                closeHistoryModal
            );

        }


        if (backdrop) {

            backdrop.addEventListener(
                "click",
                closeHistoryModal
            );

        }


        document.addEventListener(
            "keydown",
            (event) => {

                if (
                    event.key === "Escape"
                ) {

                    closeHistoryModal();

                }

            }
        );

    }
);
// ======================================================
// GET FILE NAME
// ======================================================

function getFileName(filePath) {

    if (!filePath) {

        return "Unknown file";

    }

    const normalized =
        String(filePath).replace(/\\/g, "/");

    const parts =
        normalized.split("/");

    return parts[parts.length - 1];

}
// ======================================================
// RENDER HISTORICAL FINDINGS
// ======================================================

function renderHistoryFindings(findings) {

    const findingsList = document.getElementById(
        "historyFindingsList"
    );

    const findingsCount = document.getElementById(
        "historyFindingsCount"
    );


    if (!findingsList) {

        return;

    }


    // Clear previous findings

    findingsList.innerHTML = "";


    // Update count

    const total = findings ? findings.length : 0;


    if (findingsCount) {

        findingsCount.textContent =
            `${total} FINDING${total === 1 ? "" : "S"}`;

    }


    // Empty state

    if (!findings || findings.length === 0) {

        findingsList.innerHTML = `

            <div class="history-findings-empty">

                🛡

                <span>
                    No detailed findings are available
                    for this historical scan.
                </span>

            </div>

        `;

        return;

    }


    // Create finding cards

    findings.forEach((finding) => {

        const findingItem = document.createElement(
            "div"
        );


        findingItem.className =
            "history-finding-item";


        const severity =
            (finding.severity || "LOW")
                .toUpperCase();


        const fileName =
            getFileName(finding.file_path);


        findingItem.innerHTML = `

            <div class="history-finding-main">

                <div class="history-finding-top">

                    <span
                        class="
                            severity-badge
                            ${severity.toLowerCase()}
                        "
                    >
                        ${severity}
                    </span>


                    <span class="history-finding-arrow">
                        →
                    </span>

                </div>


                <div class="history-finding-name">

                    ${finding.finding_type || "Unknown Finding"}

                </div>


                <div class="history-finding-location">

                    ${fileName}
                    ·
                    Line ${finding.line_number || "—"}

                </div>

            </div>

        `;


        // Click finding → open existing finding modal
findingItem.addEventListener(
    "click",
    () => {

        openFindingModal(finding);

    }
);


        findingsList.appendChild(
            findingItem
        );

    });

}
// ======================================================
// RENDER SECURITY CHANGE INTELLIGENCE
// ======================================================

function renderScanComparison(
    currentScan,
    containerId = "scanComparison"
) {

    const container =
    document.getElementById(
        containerId
    );

    if (!container) return;


    const change =
        currentScan?.change_analysis;


    // --------------------------------------------------
    // NO COMPARISON AVAILABLE
    // --------------------------------------------------

    if (!change || !change.available) {

        container.innerHTML = `

            <div class="comparison-empty">

                <div class="comparison-empty-icon">
                    ↔
                </div>

                <strong>
                    No Previous Scan
                </strong>

                <span>
                    Run another scan to compare
                    security posture over time.
                </span>

            </div>

        `;

        return;

    }


    // --------------------------------------------------
    // NORMALIZE VALUES
    // --------------------------------------------------

    const previousRisk =
        Number(
            change.previous_risk ?? 0
        );


    const currentRisk =
        Number(
            change.current_risk ?? 0
        );


    const riskChange =
        Number(
            change.risk_change ?? 0
        );


    const riskReduction =
        Number(
            change.risk_reduction ?? 0
        );


    const newFindings =
        Array.isArray(
            change.new_findings
        )
            ? change.new_findings
            : [];


    const resolvedFindings =
        Array.isArray(
            change.resolved_findings
        )
            ? change.resolved_findings
            : [];


    const persistentFindings =
        Array.isArray(
            change.persistent_findings
        )
            ? change.persistent_findings
            : [];


    const reappearedFindings =
        Array.isArray(
            change.reappeared_findings
        )
            ? change.reappeared_findings
            : [];


    const newCount =
        newFindings.length;


    const resolvedCount =
        resolvedFindings.length;


    const persistentCount =
        persistentFindings.length;


    const reappearedCount =
        reappearedFindings.length;


    const improved =
        Boolean(
            change.security_improved
        );


    // --------------------------------------------------
    // STATUS
    // --------------------------------------------------

    let statusTitle =
    "NO CHANGE";

let statusDescription =
    "Security posture is unchanged from the previous scan.";

let statusClass =
    "unchanged";


if (
    improved &&
    riskReduction > 0
) {

    statusTitle =
        "SECURITY IMPROVED";

    statusDescription =
        `Risk reduced by ${riskReduction} point${
            riskReduction === 1
                ? ""
                : "s"
        } compared with the previous scan.`;

    statusClass =
        "improved";

}


else if (
    improved &&
    resolvedCount > 0
) {

    statusTitle =
        "SECURITY IMPROVED";

    statusDescription =
        `${resolvedCount} finding${
            resolvedCount === 1
                ? ""
                : "s"
        } resolved, but overall project risk remains unchanged.`;

    statusClass =
        "improved";

}


else if (
    reappearedCount > 0
) {

    statusTitle =
        "EXPOSURE RETURNED";

    statusDescription =
        `${reappearedCount} finding${
            reappearedCount === 1
                ? ""
                : "s"
        } reappeared.`;

    statusClass =
        "worsened";

}


else if (
    riskChange > 0
) {

    statusTitle =
        "SECURITY POSTURE WORSENED";

    statusDescription =
        `Risk increased by ${riskChange} point${
            riskChange === 1
                ? ""
                : "s"
        }.`;

    statusClass =
        "worsened";

}

    // --------------------------------------------------
    // RISK DIRECTION
    // --------------------------------------------------

    let changeText =
        "NO CHANGE";

    if (riskChange < 0) {

        changeText =
            `↓ ${Math.abs(
                riskChange
            )} POINT${
                Math.abs(riskChange) === 1
                    ? ""
                    : "S"
            }`;

    }

    else if (riskChange > 0) {

        changeText =
            `↑ ${riskChange} POINT${
                riskChange === 1
                    ? ""
                    : "S"
            }`;

    }


    // --------------------------------------------------
    // FINAL UI
    // --------------------------------------------------

    container.innerHTML = `

        <div class="
            change-intelligence-card
            ${statusClass}
        ">


            <div class="change-intelligence-header">

                <div>

                    <div class="change-intelligence-label">
                        SECURITY CHANGE
                    </div>

                    <div class="change-intelligence-title">
                        ${statusTitle}
                    </div>

                    <div class="change-intelligence-description">
                        ${statusDescription}
                    </div>

                </div>


                <div class="change-intelligence-badge">
                    ${improved
                        ? "IMPROVED"
                        : riskChange > 0
                            ? "WORSENED"
                            : "STABLE"
                    }
                </div>

            </div>


            <div class="change-risk-hero">

                <div class="change-risk-block">

                    <span>
                        PREVIOUS RISK
                    </span>

                    <strong>
                        ${previousRisk}
                    </strong>

                    <small>
                        /100
                    </small>

                </div>


                <div class="change-risk-arrow">
                    →
                </div>


                <div class="change-risk-block current">

                    <span>
                        CURRENT RISK
                    </span>

                    <strong>
                        ${currentRisk}
                    </strong>

                    <small>
                        /100
                    </small>

                </div>


                <div class="
                    change-risk-delta
                    ${statusClass}
                ">

                    ${changeText}

                </div>

            </div>


            <div class="change-finding-grid">

                <div class="
                    change-finding-card
                    new
                ">

                    <strong>
                        ${newCount}
                    </strong>

                    <span>
                        NEW
                    </span>

                </div>


                <div class="
                    change-finding-card
                    resolved
                ">

                    <strong>
                        ${resolvedCount}
                    </strong>

                    <span>
                        RESOLVED
                    </span>

                </div>


                <div class="
                    change-finding-card
                    persistent
                ">

                    <strong>
                        ${persistentCount}
                    </strong>

                    <span>
                        PERSISTENT
                    </span>

                </div>


                <div class="
                    change-finding-card
                    reappeared
                ">

                    <strong>
                        ${reappearedCount}
                    </strong>

                    <span>
                        REAPPEARED
                    </span>

                </div>

            </div>


            <div class="change-result-strip">

    <div>

        <span>
            RISK REDUCTION
        </span>

        <strong>
            ${riskReduction > 0
                ? riskReduction
                : "NONE"}
        </strong>

    </div>

                <div>

                    <span>
                        SECURITY STATE
                    </span>

                    <strong>
                        ${
                            improved
                                ? "IMPROVED"
                                : reappearedCount > 0
                                    ? "EXPOSURE RETURNED"
                                    : riskChange > 0
                                        ? "WORSENED"
                                        : "STABLE"
                        }
                    </strong>

                </div>

            </div>


        </div>

    `;
}
