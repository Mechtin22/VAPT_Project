import {
    Shield,
    Bug,
    AlertTriangle,
    CheckCircle,
    Activity
} from "lucide-react";

import {
    useEffect,
    useState
} from "react";

import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer
} from "recharts";

import api from "../services/api";

import StatCard from "../components/StatCard";

function Dashboard() {
    const [findings, setFindings] = useState([]);
    const [assessments, setAssessments] = useState([]);
    const [scanRuns, setScanRuns] = useState([]);
    const [loading, setLoading] = useState(true);
    const [loadError, setLoadError] = useState("");

    useEffect(() => {
        let cancelled = false;

        async function loadDashboard() {
            setLoading(true);
            setLoadError("");

            const errors = [];

            try {
                // Load assessments and findings from the database.
                const [
                    assessmentsResult,
                    findingsResult
                ] = await Promise.allSettled([
                    api.get("/assessments"),
                    api.get("/findings")
                ]);

                if (cancelled) return;

                let assessmentRows = [];
                let findingRows = [];

                if (assessmentsResult.status === "fulfilled") {
                    const data = assessmentsResult.value.data;

                    assessmentRows = Array.isArray(data)
                        ? data
                        : [];

                    setAssessments(assessmentRows);
                } else {
                    setAssessments([]);
                    errors.push("Assessments could not be loaded.");
                }

                if (findingsResult.status === "fulfilled") {
                    const data = findingsResult.value.data;

                    findingRows = Array.isArray(data)
                        ? data
                        : [];

                    setFindings(findingRows);
                } else {
                    setFindings([]);
                    errors.push("Findings could not be loaded.");
                }

                // Load scan history for every assessment.
                if (assessmentsResult.status === "fulfilled") {
                    const scanResults = await Promise.allSettled(
                        assessmentRows.map((assessment) =>
                            api.get(`/scans/${assessment.id}`)
                        )
                    );

                    if (cancelled) return;

                    const allScans = [];

                    scanResults.forEach((result, index) => {
                        if (result.status === "rejected") {
                            errors.push(
                                `Scan history could not be loaded for assessment #${assessmentRows[index].id}.`
                            );
                            return;
                        }

                        const data = result.value.data;

                        if (!Array.isArray(data)) return;

                        data.forEach((scan) => {
                            allScans.push({
                                ...scan,
                                assessment_id:
                                    scan.assessment_id ??
                                    assessmentRows[index].id
                            });
                        });
                    });

                    setScanRuns(allScans);
                } else {
                    setScanRuns([]);
                }

                if (!cancelled) {
                    setLoadError(errors.join(" "));
                }
            } catch (error) {
                if (!cancelled) {
                    console.error(
                        "Error loading dashboard:",
                        error
                    );

                    setLoadError(
                        "Some dashboard data could not be loaded. Progress may be incomplete."
                    );
                }
            } finally {
                if (!cancelled) {
                    setLoading(false);
                }
            }
        }

        loadDashboard();

        return () => {
            cancelled = true;
        };
    }, []);

    // ---------------------------------------------------------
    // FINDING COUNTS
    // ---------------------------------------------------------

    const high = findings.filter(
        (finding) =>
            finding.severity === "High" ||
            finding.severity === "Critical"
    ).length;

    const medium = findings.filter(
        (finding) => finding.severity === "Medium"
    ).length;

    const low = findings.filter(
        (finding) =>
            finding.severity === "Low" ||
            finding.severity === "Info"
    ).length;

    const resolved = findings.filter(
        (finding) => finding.status === "Resolved"
    ).length;

    const chartData = [
        {
            name: "High / Critical",
            value: high
        },
        {
            name: "Medium",
            value: medium
        },
        {
            name: "Low / Info",
            value: low
        }
    ];

    const COLORS = [
        "#ef4444",
        "#f59e0b",
        "#38bdf8"
    ];

    // ---------------------------------------------------------
    // SCAN COUNTS
    // ---------------------------------------------------------

    const totalScans = scanRuns.length;

    const completedScans = scanRuns.filter(
        (scan) =>
            String(scan.status).toLowerCase() === "completed"
    ).length;

    const runningScans = scanRuns.filter(
        (scan) =>
            String(scan.status).toLowerCase() === "running"
    ).length;

    const failedScans = scanRuns.filter(
        (scan) =>
            String(scan.status).toLowerCase() === "failed"
    ).length;

    const pagesScanned = scanRuns.reduce(
        (total, scan) =>
            total + Number(scan.pages_scanned || 0),
        0
    );

    const assessmentsWithScans = new Set(
        scanRuns.map((scan) => String(scan.assessment_id))
    ).size;

    // ---------------------------------------------------------
    // DYNAMIC PROGRESS
    //
    // These percentages are calculated using database records.
    // No stored scan history means zero scan-related progress.
    // ---------------------------------------------------------

    const assessmentCoverage = assessments.length > 0
        ? Math.round(
            (assessmentsWithScans / assessments.length) * 100
        )
        : 0;

    const scanCompletion = totalScans > 0
        ? Math.round(
            (completedScans / totalScans) * 100
        )
        : 0;

    const findingResolution = findings.length > 0
        ? Math.round(
            (resolved / findings.length) * 100
        )
        : 0;

    // ---------------------------------------------------------
    // DYNAMIC PROJECT STATUS
    // ---------------------------------------------------------

    let projectStatus = "NO SCANS";

    if (runningScans > 0) {
        projectStatus = "SCANNING";
    } else if (totalScans > 0 && completedScans === totalScans) {
        projectStatus = "SCANS COMPLETED";
    } else if (totalScans > 0) {
        projectStatus = "REVIEW REQUIRED";
    }

    let projectSubtitle = "No scan history recorded";

    if (assessments.length === 0) {
        projectSubtitle = "Create an assessment to get started";
    } else if (totalScans > 0) {
        projectSubtitle =
            `${completedScans} of ${totalScans} scans completed`;
    }

    const progressDescription = totalScans === 0
        ? "No scan history is currently recorded."
        : `${assessmentsWithScans} of ${assessments.length} assessments have scan history.`;

    // ---------------------------------------------------------
    // RENDER
    // ---------------------------------------------------------

    return (
        <div>
            <section className="welcome">
                <div>
                    <p className="eyebrow">
                        SECURITY OPERATIONS
                    </p>

                    <h2>
                        VAPT Overview
                    </h2>

                    <p>
                        Monitor your authorized
                        local web application
                        security assessment.
                    </p>
                </div>

                <div className="target-pill">
                    <Activity size={17} />

                    <span>
                        Target: localhost/DVWA
                    </span>
                </div>
            </section>

            {loadError && (
                <div className="panel">
                    <p role="status">
                        {loadError}
                    </p>
                </div>
            )}

            {/* -------------------------------------------------
                SUMMARY CARDS
            ------------------------------------------------- */}

            <div className="stats-grid">
                <StatCard
                    title="Total Findings"
                    value={loading ? "..." : findings.length}
                    subtitle="Recorded"
                    icon={Bug}
                />

                <StatCard
                    title="High / Critical"
                    value={loading ? "..." : high}
                    subtitle="Attention"
                    icon={AlertTriangle}
                />

                <StatCard
                    title="Resolved"
                    value={loading ? "..." : resolved}
                    subtitle="Marked resolved"
                    icon={CheckCircle}
                />

                <StatCard
                    title="Assessments"
                    value={loading ? "..." : assessments.length}
                    subtitle={loading ? "Loading..." : projectSubtitle}
                    icon={Shield}
                />
            </div>

            {/* -------------------------------------------------
                CHART AND LIVE PROGRESS
            ------------------------------------------------- */}

            <div className="dashboard-grid">
                <div className="panel chart-panel">
                    <div className="panel-header">
                        <div>
                            <h3>
                                Severity Distribution
                            </h3>

                            <p>
                                Recorded findings
                            </p>
                        </div>
                    </div>

                    <div className="chart">
                        {findings.length === 0 && !loading ? (
                            <div className="empty">
                                <Shield size={32} />

                                <p>
                                    No findings available to display.
                                </p>
                            </div>
                        ) : (
                            <ResponsiveContainer
                                width="100%"
                                height={300}
                            >
                                <PieChart>
                                    <Pie
                                        data={chartData}
                                        dataKey="value"
                                        nameKey="name"
                                        cx="50%"
                                        cy="50%"
                                        outerRadius={100}
                                        innerRadius={60}
                                    >
                                        {chartData.map(
                                            (item, index) => (
                                                <Cell
                                                    key={item.name}
                                                    fill={COLORS[index]}
                                                />
                                            )
                                        )}
                                    </Pie>

                                    <Tooltip />
                                </PieChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </div>

                <div className="panel">
                    <div className="panel-header">
                        <div>
                            <h3>
                                Assessment Progress
                            </h3>

                            <p>
                                {loading
                                    ? "Loading current project status..."
                                    : progressDescription}
                            </p>
                        </div>

                        <span className="badge blue">
                            {loading ? "LOADING" : projectStatus}
                        </span>
                    </div>

                    <div className="progress-list">
                        <Progress
                            name="Assessment Coverage"
                            value={loading ? 0 : assessmentCoverage}
                        />

                        <Progress
                            name="Scan Completion"
                            value={loading ? 0 : scanCompletion}
                        />

                        <Progress
                            name="Findings Resolved"
                            value={loading ? 0 : findingResolution}
                        />
                    </div>

                    <div className="progress-list">
                        <div className="progress-item">
                            <div className="progress-label">
                                <span>
                                    Total Scan Runs
                                </span>

                                <strong>
                                    {loading ? "..." : totalScans}
                                </strong>
                            </div>
                        </div>

                        <div className="progress-item">
                            <div className="progress-label">
                                <span>
                                    Pages Scanned
                                </span>

                                <strong>
                                    {loading ? "..." : pagesScanned}
                                </strong>
                            </div>
                        </div>

                        <div className="progress-item">
                            <div className="progress-label">
                                <span>
                                    Failed Scans
                                </span>

                                <strong>
                                    {loading ? "..." : failedScans}
                                </strong>
                            </div>
                        </div>
                    </div>

                    {!loading && totalScans === 0 && (
                        <div className="empty">
                            <Shield size={28} />

                            <p>
                                No scan history found. Progress will update
                                when a new scan is recorded.
                            </p>
                        </div>
                    )}
                </div>
            </div>

            {/* -------------------------------------------------
                RECENT FINDINGS
            ------------------------------------------------- */}

            <div className="panel">
                <div className="panel-header">
                    <div>
                        <h3>
                            Recent Findings
                        </h3>

                        <p>
                            Latest recorded security observations
                        </p>
                    </div>
                </div>

                <div className="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>
                                    Vulnerability
                                </th>

                                <th>
                                    Module
                                </th>

                                <th>
                                    Severity
                                </th>

                                <th>
                                    Status
                                </th>
                            </tr>
                        </thead>

                        <tbody>
                            {findings
                                .slice(0, 5)
                                .map((finding) => (
                                    <tr key={finding.id}>
                                        <td>
                                            <strong>
                                                {finding.vulnerability}
                                            </strong>
                                        </td>

                                        <td>
                                            {finding.affected_module || "—"}
                                        </td>

                                        <td>
                                            <span
                                                className={
                                                    `severity ${
                                                        String(
                                                            finding.severity || "info"
                                                        ).toLowerCase()
                                                    }`
                                                }
                                            >
                                                {finding.severity || "Info"}
                                            </span>
                                        </td>

                                        <td>
                                            {finding.status || "Open"}
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>

                    {!loading && findings.length === 0 && (
                        <div className="empty">
                            <Shield size={32} />

                            <p>
                                No findings recorded yet.
                            </p>
                        </div>
                    )}

                    {loading && (
                        <div className="empty">
                            <p>
                                Loading findings...
                            </p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

// -------------------------------------------------------------
// REUSABLE PROGRESS BAR
// -------------------------------------------------------------

function Progress({ name, value }) {
    const safeValue = Math.max(
        0,
        Math.min(100, Number(value) || 0)
    );

    return (
        <div className="progress-item">
            <div className="progress-label">
                <span>
                    {name}
                </span>

                <strong>
                    {safeValue}%
                </strong>
            </div>

            <div className="progress-track">
                <div
                    className="progress-fill"
                    style={{
                        width: `${safeValue}%`
                    }}
                />
            </div>
        </div>
    );
}

export default Dashboard;