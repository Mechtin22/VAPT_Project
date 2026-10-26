import { useEffect, useState } from "react";

import {
    RefreshCcw,
    Play,
    Loader2,
    CheckCircle,
    XCircle,
    AlertTriangle,
    ClipboardCheck
} from "lucide-react";

import api from "../services/api";

const CONFIGURATION_CHECKS = new Set([
    "missing security headers",
    "missing clickjacking protection",
    "cookie missing httponly",
    "cookie missing samesite",
    "cookie missing secure",
    "server technology information disclosure"
]);

function normalizeName(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function formatDate(value) {
    if (!value) return "-";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "-";
    }

    return date.toLocaleString();
}

function resultClass(result) {
    switch (result) {
        case "Pass":
            return "retest-result-pass";
        case "Fail":
            return "retest-result-fail";
        default:
            return "retest-result-inconclusive";
    }
}

function ResultIcon({ result }) {
    if (result === "Pass") {
        return <CheckCircle size={17} />;
    }

    if (result === "Fail") {
        return <XCircle size={17} />;
    }

    return <AlertTriangle size={17} />;
}

function Retesting() {
    const [assessments, setAssessments] = useState([]);
    const [findings, setFindings] = useState([]);
    const [retests, setRetests] = useState([]);

    const [assessmentFilter, setAssessmentFilter] = useState("all");
    const [findingId, setFindingId] = useState("");

    const [manualResult, setManualResult] = useState("Pass");
    const [manualNotes, setManualNotes] = useState("");

    const [loading, setLoading] = useState(true);
    const [savingManual, setSavingManual] = useState(false);
    const [automatedFindingId, setAutomatedFindingId] = useState(null);

    const [notice, setNotice] = useState(null);

    // =====================================================
    // LOAD PAGE DATA
    // =====================================================

    const loadData = async (showLoading = false) => {
        if (showLoading) {
            setLoading(true);
        }

        try {
            const [
                assessmentsResponse,
                findingsResponse,
                retestsResponse
            ] = await Promise.all([
                api.get("/assessments"),
                api.get("/findings"),
                api.get("/retests")
            ]);

            setAssessments(
                Array.isArray(assessmentsResponse.data)
                    ? assessmentsResponse.data
                    : []
            );

            setFindings(
                Array.isArray(findingsResponse.data)
                    ? findingsResponse.data
                    : []
            );

            setRetests(
                Array.isArray(retestsResponse.data)
                    ? retestsResponse.data
                    : []
            );

            return true;
        } catch (error) {
            console.error("Failed to load retesting data:", error);

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    "Failed to load retesting data. Check the backend and database migration."
            });

            return false;
        } finally {
            if (showLoading) {
                setLoading(false);
            }
        }
    };

    useEffect(() => {
        loadData(true);

        // Initial page load only.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // =====================================================
    // FINDING SELECTION
    // =====================================================

    const filteredFindings = findings.filter((finding) => {
        if (assessmentFilter === "all") {
            return true;
        }

        return (
            Number(finding.assessment_id) ===
            Number(assessmentFilter)
        );
    });

    const selectedFinding = findings.find(
        (finding) =>
            Number(finding.id) === Number(findingId)
    );

    // =====================================================
    // AUTOMATED RESULT COMPARISON
    // =====================================================
    //
    // Match found:
    //   Fail - same vulnerability category detected again.
    //
    // Match absent for supported passive configuration checks:
    //   Pass - a completed scan checked HTML responses and did
    //   not reproduce that configuration finding.
    //
    // Match absent for other categories:
    //   Inconclusive - category-specific coverage is not exposed
    //   sufficiently to prove remediation.
    // =====================================================

    const classifyAutomatedResult = (scanData, finding) => {
        const scanFindings = Array.isArray(scanData.findings)
            ? scanData.findings
            : Array.isArray(scanData.categories)
                ? scanData.categories
                : [];

        const originalCategory = normalizeName(
            finding.vulnerability
        );

        const matchingFinding = scanFindings.find((item) => {
            const categoryName = normalizeName(
                item.vulnerability || item.category
            );

            return categoryName === originalCategory;
        });

        if (matchingFinding) {
            const occurrences = Number(
                matchingFinding.occurrence_count || 0
            );

            return {
                result: "Fail",
                notes:
                    `Automated retest Scan #${scanData.scan_number}: ` +
                    `"${finding.vulnerability}" was detected again. ` +
                    (
                        occurrences > 0
                            ? `${occurrences} occurrence(s) were reported. `
                            : ""
                    ) +
                    "The issue remains detectable and requires remediation."
            };
        }

        const htmlPagesScanned = Number(
            scanData.html_pages_scanned || 0
        );

        if (
            CONFIGURATION_CHECKS.has(originalCategory) &&
            htmlPagesScanned > 0
        ) {
            return {
                result: "Pass",
                notes:
                    `Automated retest Scan #${scanData.scan_number} completed. ` +
                    `The scanner checked ${htmlPagesScanned} HTML page(s) and ` +
                    `did not reproduce "${finding.vulnerability}". ` +
                    "This result applies only to the configuration check and scanned responses."
            };
        }

        return {
            result: "Inconclusive",
            notes:
                `Automated retest Scan #${scanData.scan_number} completed, ` +
                `but did not report "${finding.vulnerability}". ` +
                "The current scan response does not provide enough " +
                "category-specific coverage to prove remediation. " +
                "Manually validate the original endpoint and parameter before marking this finding Resolved."
        };
    };

    // =====================================================
    // RUN AUTOMATED RETEST
    // =====================================================

    const runAutomatedRetest = async () => {
        if (!selectedFinding) {
            setNotice({
                type: "error",
                message: "Select a finding to retest."
            });

            return;
        }

        const assessment = assessments.find(
            (item) =>
                Number(item.id) ===
                Number(selectedFinding.assessment_id)
        );

        if (!assessment) {
            setNotice({
                type: "error",
                message:
                    "The selected finding's assessment could not be found."
            });

            return;
        }

        const confirmed = window.confirm(
            `Run a new automated DVWA scan to retest:\n\n` +
            `${selectedFinding.vulnerability}\n` +
            `Assessment: ${assessment.title}\n` +
            `Target: ${assessment.target_url}\n\n` +
            "The scan will create a new scan-history entry. Continue?"
        );

        if (!confirmed) {
            return;
        }

        setAutomatedFindingId(selectedFinding.id);
        setNotice(null);

        try {
            // The existing scan endpoint runs the scanner and saves
            // the resulting scan, findings and evidence.
            const scanResponse = await api.post(
                `/scans/${assessment.id}`
            );

            const scanData = scanResponse.data || {};

            if (!scanData.scan_id) {
                throw new Error(
                    "The scan completed without returning a scan ID."
                );
            }

            const comparison = classifyAutomatedResult(
                scanData,
                selectedFinding
            );

            const notes = comparison.notes;

            // Link the retest to the new completed scan.
            await api.post("/retests", {
                finding_id: Number(selectedFinding.id),
                retest_scan_id: Number(scanData.scan_id),
                method: "Automated",
                result: comparison.result,
                notes
            });

            await loadData(false);

            setNotice({
                type:
                    comparison.result === "Pass"
                        ? "success"
                        : comparison.result === "Fail"
                            ? "error"
                            : "warning",
                message:
                    `Automated retest recorded: ${comparison.result}\n` +
                    `Scan #${scanData.scan_number}\n` +
                    `${notes}`
            });
        } catch (error) {
            console.error("Automated retest failed:", error);

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    error.response?.data?.message ||
                    error.message ||
                    "Automated retest failed."
            });
        } finally {
            setAutomatedFindingId(null);
        }
    };

    // =====================================================
    // RECORD MANUAL RETEST
    // =====================================================

    const recordManualRetest = async (event) => {
        event.preventDefault();
        setNotice(null);

        if (!selectedFinding) {
            setNotice({
                type: "error",
                message: "Select a finding."
            });

            return;
        }

        if (
            manualResult === "Pass" &&
            !manualNotes.trim()
        ) {
            setNotice({
                type: "error",
                message:
                    "Add validation notes before marking a finding as Pass."
            });

            return;
        }

        setSavingManual(true);

        try {
            await api.post("/retests", {
                finding_id: Number(selectedFinding.id),
                result: manualResult,
                notes: manualNotes.trim(),
                method: "Manual",
                retest_scan_id: null
            });

            setManualNotes("");
            setManualResult("Pass");

            await loadData(false);

            setNotice({
                type:
                    manualResult === "Pass"
                        ? "success"
                        : manualResult === "Fail"
                            ? "error"
                            : "warning",
                message:
                    `Manual retest recorded: ${manualResult}.`
            });
        } catch (error) {
            console.error("Manual retest failed:", error);

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    "Failed to record manual retest."
            });
        } finally {
            setSavingManual(false);
        }
    };

    // =====================================================
    // RENDER
    // =====================================================

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        VERIFICATION
                    </p>

                    <h2>
                        Retesting
                    </h2>

                    <p>
                        Verify remediation, compare new scan results,
                        and keep a traceable retest history.
                    </p>
                </div>

                <button
                    type="button"
                    className="secondary-btn"
                    onClick={() => loadData(true)}
                    disabled={
                        loading ||
                        savingManual ||
                        automatedFindingId !== null
                    }
                >
                    <RefreshCcw size={16} />
                    Refresh
                </button>
            </div>

            {notice && (
                <div
                    className="panel"
                    role="status"
                    aria-live="polite"
                    style={{
                        whiteSpace: "pre-line",
                        borderLeft:
                            `4px solid ${
                                notice.type === "success"
                                    ? "#16a34a"
                                    : notice.type === "warning"
                                        ? "#d97706"
                                        : "#dc2626"
                            }`
                    }}
                >
                    <strong>
                        {notice.type === "success"
                            ? "Retest completed"
                            : notice.type === "warning"
                                ? "Manual validation required"
                                : "Retest notice"}
                    </strong>

                    <p style={{ marginTop: "8px" }}>
                        {notice.message}
                    </p>
                </div>
            )}

            {/* FINDING SELECTION */}

            <div className="panel">
                <h3>
                    Select Finding
                </h3>

                <div className="form-grid">
                    <label>
                        Assessment filter

                        <select
                            value={assessmentFilter}
                            onChange={(event) => {
                                setAssessmentFilter(event.target.value);
                                setFindingId("");
                            }}
                        >
                            <option value="all">
                                All assessments
                            </option>

                            {assessments.map((assessment) => (
                                <option
                                    key={assessment.id}
                                    value={assessment.id}
                                >
                                    {assessment.title}
                                </option>
                            ))}
                        </select>
                    </label>

                    <label>
                        Finding to retest

                        <select
                            value={findingId}
                            onChange={(event) =>
                                setFindingId(event.target.value)
                            }
                            disabled={loading}
                        >
                            <option value="">
                                Select finding
                            </option>

                            {filteredFindings.map((finding) => (
                                <option
                                    key={finding.id}
                                    value={finding.id}
                                >
                                    #{finding.id} —{" "}
                                    {finding.vulnerability} —{" "}
                                    {finding.severity} —{" "}
                                    {finding.status}
                                </option>
                            ))}
                        </select>
                    </label>
                </div>

                {selectedFinding && (
                    <div
                        style={{
                            marginTop: "18px",
                            padding: "16px",
                            border: "1px solid var(--border-color, #29415c)",
                            borderRadius: "10px"
                        }}
                    >
                        <h3>
                            {selectedFinding.vulnerability}
                        </h3>

                        <p>
                            <strong>Assessment:</strong>{" "}
                            {selectedFinding.assessment_title || "Assessment"}
                        </p>

                        <p>
                            <strong>Severity:</strong>{" "}
                            {selectedFinding.severity || "Unknown"}
                        </p>

                        <p>
                            <strong>Current status:</strong>{" "}
                            {selectedFinding.status || "Open"}
                        </p>

                        {selectedFinding.affected_module && (
                            <p>
                                <strong>Affected location:</strong>{" "}
                                {selectedFinding.affected_module}
                            </p>
                        )}

                        {selectedFinding.description && (
                            <p>
                                {selectedFinding.description}
                            </p>
                        )}
                    </div>
                )}

                <div
                    style={{
                        display: "flex",
                        gap: "12px",
                        flexWrap: "wrap",
                        marginTop: "18px"
                    }}
                >
                    <button
                        type="button"
                        className="primary-btn"
                        onClick={runAutomatedRetest}
                        disabled={
                            !selectedFinding ||
                            loading ||
                            savingManual ||
                            automatedFindingId !== null
                        }
                    >
                        {automatedFindingId !== null ? (
                            <Loader2
                                size={17}
                                className="spin"
                            />
                        ) : (
                            <Play size={17} />
                        )}

                        {automatedFindingId !== null
                            ? "Scanning for retest..."
                            : "Run Automated Retest"}
                    </button>
                </div>

                <p style={{ marginTop: "12px" }}>
                    The automated action creates a new scan. A matching
                    detection is recorded as Fail. A missing configuration
                    finding may be recorded as Pass when the scan checked
                    HTML pages; other undetected categories remain
                    Inconclusive until their test coverage can be verified.
                </p>
            </div>

            {/* MANUAL RETEST */}

            <div className="panel">
                <h3>
                    Record Manual Retest
                </h3>

                <form
                    onSubmit={recordManualRetest}
                    className="form-grid"
                >
                    <label>
                        Validation result

                        <select
                            value={manualResult}
                            onChange={(event) =>
                                setManualResult(event.target.value)
                            }
                            disabled={
                                savingManual ||
                                automatedFindingId !== null
                            }
                        >
                            <option value="Pass">
                                Pass — validated as fixed
                            </option>

                            <option value="Fail">
                                Fail — still vulnerable
                            </option>

                            <option value="Inconclusive">
                                Inconclusive — unable to verify
                            </option>
                        </select>
                    </label>

                    <label>
                        Retest notes

                        <textarea
                            placeholder="Describe the validation performed and the evidence observed."
                            value={manualNotes}
                            onChange={(event) =>
                                setManualNotes(event.target.value)
                            }
                            rows={4}
                            disabled={
                                savingManual ||
                                automatedFindingId !== null
                            }
                        />
                    </label>

                    <button
                        type="submit"
                        className="primary-btn"
                        disabled={
                            !selectedFinding ||
                            savingManual ||
                            automatedFindingId !== null
                        }
                    >
                        {savingManual ? (
                            <Loader2 size={17} className="spin" />
                        ) : (
                            <ClipboardCheck size={17} />
                        )}

                        Record Manual Result
                    </button>
                </form>
            </div>

            {/* RETEST HISTORY */}

            <div className="panel">
                <div className="panel-header">
                    <div>
                        <h3>
                            Retest History
                        </h3>

                        <p>
                            Historical outcomes and linked scan records
                        </p>
                    </div>
                </div>

                {loading ? (
                    <div className="empty-large">
                        Loading retest history...
                    </div>
                ) : retests.length === 0 ? (
                    <div className="empty-large">
                        No retests recorded yet.
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Finding</th>
                                    <th>Assessment</th>
                                    <th>Original Scan</th>
                                    <th>Retest Scan</th>
                                    <th>Method</th>
                                    <th>Result</th>
                                    <th>Notes</th>
                                    <th>Tested</th>
                                </tr>
                            </thead>

                            <tbody>
                                {retests.map((retest) => (
                                    <tr key={retest.id}>
                                        <td>
                                            <strong>
                                                {retest.vulnerability}
                                            </strong>

                                            <div>
                                                #{retest.finding_id}
                                            </div>
                                        </td>

                                        <td>
                                            {retest.assessment_title || "-"}
                                        </td>

                                        <td>
                                            {retest.original_scan_number
                                                ? `#${retest.original_scan_number}`
                                                : "-"}
                                        </td>

                                        <td>
                                            {retest.retest_scan_number
                                                ? `#${retest.retest_scan_number}`
                                                : "-"}
                                        </td>

                                        <td>
                                            {retest.method || "Manual"}
                                        </td>

                                        <td>
                                            <span
                                                className={
                                                    resultClass(retest.result)
                                                }
                                                style={{
                                                    display: "inline-flex",
                                                    alignItems: "center",
                                                    gap: "6px"
                                                }}
                                            >
                                                <ResultIcon
                                                    result={retest.result}
                                                />

                                                {retest.result}
                                            </span>
                                        </td>

                                        <td
                                            style={{
                                                minWidth: "260px",
                                                whiteSpace: "pre-line"
                                            }}
                                        >
                                            {retest.notes || "-"}
                                        </td>

                                        <td>
                                            {formatDate(retest.tested_at)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}

export default Retesting;