import { useEffect, useState } from "react";
import api from "../services/api";

function Findings() {
    const [assessments, setAssessments] = useState([]);
    const [scanHistory, setScanHistory] = useState({});

    const [expandedAssessments, setExpandedAssessments] =
        useState({});

    const [expandedScans, setExpandedScans] =
        useState({});

    const [expandedFindings, setExpandedFindings] =
        useState({});

    const [loading, setLoading] = useState(true);
    const [clearingId, setClearingId] = useState(null);
    const [deletingScanId, setDeletingScanId] = useState(null);
    const [notice, setNotice] = useState(null);


    // LOAD ASSESSMENTS AND SCAN HISTORY

    const loadAssessments = async (showLoading = false) => {
        if (showLoading) setLoading(true);

        try {
            const response = await api.get("/assessments");

            const list = Array.isArray(response.data)
                ? response.data
                : [];

            setAssessments(list);

            const histories = await Promise.all(
                list.map(async (assessment) => {
                    try {
                        const scanResponse = await api.get(
                            `/scans/${assessment.id}`
                        );

                        return [
                            assessment.id,
                            Array.isArray(scanResponse.data)
                                ? scanResponse.data
                                : []
                        ];
                    } catch (error) {
                        console.error(
                            `Failed to load scans for assessment ${assessment.id}`,
                            error
                        );

                        return [assessment.id, []];
                    }
                })
            );

            setScanHistory(Object.fromEntries(histories));
            return true;
        } catch (error) {
            console.error("Failed to load assessments:", error);

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    "Failed to load assessments."
            });

            return false;
        } finally {
            if (showLoading) setLoading(false);
        }
    };

    useEffect(() => {
        loadAssessments(true);
        // Initial load only.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);


    // EXPAND / COLLAPSE

    const toggleAssessment = (id) => {
        setExpandedAssessments((previous) => ({
            ...previous,
            [id]: !previous[id]
        }));
    };

    const toggleScan = (id) => {
        setExpandedScans((previous) => ({
            ...previous,
            [id]: !previous[id]
        }));
    };

    const toggleFinding = (id) => {
        setExpandedFindings((previous) => ({
            ...previous,
            [id]: !previous[id]
        }));
    };


    // CLEAR HISTORY

    const clearHistory = async (assessment) => {
        const confirmed = window.confirm(
            `Clear all scan history for "${assessment.title}"?\n\n` +
            "This removes scan runs, findings, occurrences, retests " +
            "and linked evidence records. The assessment itself remains. " +
            "This cannot be undone."
        );

        if (!confirmed) return;

        setClearingId(assessment.id);
        setNotice(null);

        try {
            const response = await api.delete(
                `/scans/${assessment.id}/history`
            );

            const data = response.data || {};

            await loadAssessments(false);

            setNotice({
                type: data.file_cleanup_warnings?.length
                    ? "warning"
                    : "success",

                message: [
                    data.message || "Scan history cleared.",
                    `Scans deleted: ${data.deleted_scans ?? 0}`,
                    `Findings deleted: ${data.deleted_findings ?? 0}`,
                    `Occurrences deleted: ${data.deleted_occurrences ?? 0}`,
                    `Retests deleted: ${data.deleted_retests ?? 0}`,
                    `Evidence records deleted: ${data.deleted_evidence_records ?? 0}`,
                    `Automatic evidence files deleted: ${data.deleted_automatic_evidence_files ?? 0}`,
                    `Manual evidence files deleted: ${data.deleted_manual_evidence_files ?? 0}`
                ].join("\n"),

                warnings: data.file_cleanup_warnings || []
            });
        } catch (error) {
            console.error("Failed to clear scan history:", error);

            setNotice({
                type:
                    error.response?.status === 409
                        ? "warning"
                        : "error",

                message:
                    error.response?.data?.error ||
                    error.response?.data?.message ||
                    "Failed to clear scan history."
            });
        } finally {
            setClearingId(null);
        }
    };


    // DELETE ONE SCAN

    const deleteScan = async (assessment, scan) => {
        const confirmed = window.confirm(
            `Delete Scan #${scan.scan_number} from "${assessment.title}"?\n\n` +
            "This removes the selected scan's findings, occurrences, " +
            "retests and linked evidence. Remaining scans will be renumbered."
        );

        if (!confirmed) return;

        setDeletingScanId(scan.id);
        setNotice(null);

        try {
            const response = await api.delete(
                `/scans/${assessment.id}/${scan.id}`
            );

            const data = response.data || {};

            await loadAssessments(false);

            setNotice({
                type: data.file_cleanup_warnings?.length
                    ? "warning"
                    : "success",

                message: [
                    data.message || "Scan deleted.",
                    `Deleted scan number: ${data.deleted_scan_number ?? scan.scan_number}`,
                    `Findings deleted: ${data.deleted_findings ?? 0}`,
                    `Occurrences deleted: ${data.deleted_occurrences ?? 0}`,
                    `Retests deleted: ${data.deleted_retests ?? 0}`,
                    `Evidence records deleted: ${data.deleted_evidence_records ?? 0}`,
                    `Remaining scans: ${data.remaining_scan_count ?? 0}`,
                    `Automatic evidence files deleted: ${data.deleted_automatic_evidence_files ?? 0}`,
                    `Manual evidence files deleted: ${data.deleted_manual_evidence_files ?? 0}`
                ].join("\n"),

                warnings: data.file_cleanup_warnings || []
            });
        } catch (error) {
            console.error("Failed to delete scan:", error);

            setNotice({
                type:
                    error.response?.status === 409
                        ? "warning"
                        : "error",

                message:
                    error.response?.data?.error ||
                    error.response?.data?.message ||
                    "Failed to delete scan."
            });
        } finally {
            setDeletingScanId(null);
        }
    };


    // RENDER

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        VULNERABILITY MANAGEMENT
                    </p>

                    <h2>Scan Findings</h2>

                    <p>
                        Findings are organized by assessment,
                        scan and vulnerability category.
                    </p>
                </div>

                <button
                    type="button"
                    className="secondary-btn"
                    disabled={
                        loading ||
                        clearingId !== null ||
                        deletingScanId !== null
                    }
                    onClick={() => loadAssessments(false)}
                >
                    Refresh
                </button>
            </div>


            {/* OPERATION RESULT */}

            {notice && (
                <div
                    className="panel"
                    role="status"
                    aria-live="polite"
                    style={{
                        marginBottom: "18px",
                        borderLeft: `4px solid ${
                            notice.type === "success"
                                ? "#16a34a"
                                : notice.type === "warning"
                                    ? "#d97706"
                                    : "#dc2626"
                        }`
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            gap: "16px"
                        }}
                    >
                        <div>
                            <strong>
                                {notice.type === "success"
                                    ? "Operation completed"
                                    : notice.type === "warning"
                                        ? "Completed with warnings"
                                        : "Operation failed"}
                            </strong>

                            <p
                                style={{
                                    marginTop: "8px",
                                    whiteSpace: "pre-line"
                                }}
                            >
                                {notice.message}
                            </p>

                            {notice.warnings?.length > 0 && (
                                <ul>
                                    {notice.warnings.map((warning, index) => (
                                        <li
                                            key={`${warning.scan_id || warning.file_path || index}-${index}`}
                                        >
                                            {warning.file_path ||
                                                (warning.scan_id != null
                                                    ? `Scan #${warning.scan_id}`
                                                    : warning.evidence_id != null
                                                        ? `Evidence #${warning.evidence_id}`
                                                        : "")}
                                            {": "}
                                            {warning.message}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>

                        <button
                            type="button"
                            className="secondary-btn"
                            onClick={() => setNotice(null)}
                        >
                            Dismiss
                        </button>
                    </div>
                </div>
            )}


            {loading && (
                <div className="panel">
                    Loading scan history...
                </div>
            )}


            {!loading && assessments.length === 0 && (
                <div className="panel">
                    No assessments found.
                </div>
            )}


            {/* ASSESSMENTS */}

            {!loading && assessments.map((assessment) => {
                const scans = scanHistory[assessment.id] || [];

                const assessmentOpen =
                    !!expandedAssessments[assessment.id];

                return (
                    <div
                        className="panel"
                        key={assessment.id}
                        style={{ marginBottom: "20px" }}
                    >
                        {/* ASSESSMENT HEADER */}

                        <div
                            style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                gap: "20px",
                                flexWrap: "wrap",
                                cursor: "pointer"
                            }}
                            onClick={() => toggleAssessment(assessment.id)}
                        >
                            <div>
                                <p className="eyebrow">
                                    ASSESSMENT #{assessment.id}
                                </p>

                                <h3>{assessment.title}</h3>
                                <p>{assessment.target_url}</p>
                            </div>

                            <div
                                style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "10px",
                                    flexWrap: "wrap"
                                }}
                            >
                                <span className="severity">
                                    {scans.length} scan
                                    {scans.length === 1 ? "" : "s"}
                                </span>

                                <button
                                    type="button"
                                    disabled={
                                        clearingId === assessment.id ||
                                        deletingScanId !== null
                                    }
                                    onClick={(event) => {
                                        event.stopPropagation();
                                        clearHistory(assessment);
                                    }}
                                >
                                    {clearingId === assessment.id
                                        ? "Clearing..."
                                        : "Clear History"}
                                </button>

                                <span style={{ fontSize: "22px" }}>
                                    {assessmentOpen ? "−" : "+"}
                                </span>
                            </div>
                        </div>


                        {/* SCAN HISTORY */}

                        {assessmentOpen && (
                            <div style={{ marginTop: "20px" }}>
                                {scans.length === 0 ? (
                                    <div className="empty-state">
                                        No scans have been run for this assessment.
                                    </div>
                                ) : (
                                    scans.map((scan) => {
                                        const scanOpen =
                                            !!expandedScans[scan.id];

                                        const scanFindings =
                                            Array.isArray(scan.findings)
                                                ? scan.findings
                                                : [];

                                        const scanDeleting =
                                            deletingScanId === scan.id;

                                        return (
                                            <div
                                                key={scan.id}
                                                style={{
                                                    border: "1px solid rgba(255,255,255,0.08)",
                                                    borderRadius: "10px",
                                                    marginBottom: "14px",
                                                    overflow: "hidden"
                                                }}
                                            >
                                                {/* SCAN HEADER */}

                                                <div
                                                    style={{
                                                        display: "flex",
                                                        justifyContent: "space-between",
                                                        alignItems: "center",
                                                        flexWrap: "wrap",
                                                        gap: "12px",
                                                        padding: "16px 18px",
                                                        cursor: "pointer"
                                                    }}
                                                    onClick={() => toggleScan(scan.id)}
                                                >
                                                    <div>
                                                        <strong>
                                                            Scan #{scan.scan_number}
                                                        </strong>

                                                        <div
                                                            style={{
                                                                marginTop: "6px",
                                                                opacity: 0.7,
                                                                fontSize: "13px"
                                                            }}
                                                        >
                                                            {scan.pages_scanned ?? 0}
                                                            {" pages • "}
                                                            {scan.findings_created ??
                                                                scanFindings.length}
                                                            {" categories • "}
                                                            {scan.duration_ms ?? 0}
                                                            {" ms"}
                                                        </div>
                                                    </div>

                                                    <div
                                                        style={{
                                                            display: "flex",
                                                            alignItems: "center",
                                                            gap: "12px",
                                                            flexWrap: "wrap"
                                                        }}
                                                    >
                                                        <button
                                                            type="button"
                                                            disabled={
                                                                scanDeleting ||
                                                                clearingId === assessment.id ||
                                                                String(scan.status).toLowerCase() === "running"
                                                            }
                                                            onClick={(event) => {
                                                                event.stopPropagation();
                                                                deleteScan(assessment, scan);
                                                            }}
                                                            style={{
                                                                padding: "7px 10px",
                                                                background: "#7f1d1d",
                                                                color: "#ffffff",
                                                                border: "1px solid #991b1b",
                                                                borderRadius: "6px",
                                                                cursor: scanDeleting
                                                                    ? "not-allowed"
                                                                    : "pointer",
                                                                opacity: scanDeleting
                                                                    ? 0.6
                                                                    : 1
                                                            }}
                                                        >
                                                            {scanDeleting
                                                                ? "Deleting..."
                                                                : "Delete Scan"}
                                                        </button>

                                                        <span className="severity">
                                                            {scan.status}
                                                        </span>

                                                        <span>
                                                            {scanOpen ? "−" : "+"}
                                                        </span>
                                                    </div>
                                                </div>


                                                {/* FINDINGS */}

                                                {scanOpen && (
                                                    <div
                                                        style={{
                                                            padding: "0 18px 18px"
                                                        }}
                                                    >
                                                        {scanFindings.length === 0 ? (
                                                            <div className="empty-state">
                                                                No vulnerabilities detected in this scan.
                                                            </div>
                                                        ) : (
                                                            scanFindings.map((finding) => {
                                                                const findingOpen =
                                                                    !!expandedFindings[finding.id];

                                                                const occurrences =
                                                                    Array.isArray(finding.occurrences)
                                                                        ? finding.occurrences
                                                                        : [];

                                                                return (
                                                                    <div
                                                                        key={finding.id}
                                                                        style={{
                                                                            borderTop: "1px solid rgba(255,255,255,0.06)",
                                                                            padding: "16px 0"
                                                                        }}
                                                                    >
                                                                        <div
                                                                            style={{
                                                                                display: "flex",
                                                                                justifyContent: "space-between",
                                                                                alignItems: "center",
                                                                                gap: "12px",
                                                                                cursor: "pointer"
                                                                            }}
                                                                            onClick={() =>
                                                                                toggleFinding(finding.id)
                                                                            }
                                                                        >
                                                                            <div>
                                                                                <strong
                                                                                    style={{
                                                                                        fontSize: "16px"
                                                                                    }}
                                                                                >
                                                                                    {finding.vulnerability}
                                                                                </strong>

                                                                                <div
                                                                                    style={{
                                                                                        marginTop: "6px",
                                                                                        opacity: 0.7,
                                                                                        fontSize: "13px"
                                                                                    }}
                                                                                >
                                                                                    {occurrences.length}
                                                                                    {" affected location"}
                                                                                    {occurrences.length === 1
                                                                                        ? ""
                                                                                        : "s"}
                                                                                </div>
                                                                            </div>

                                                                            <div
                                                                                style={{
                                                                                    display: "flex",
                                                                                    alignItems: "center",
                                                                                    gap: "12px"
                                                                                }}
                                                                            >
                                                                                <span
                                                                                    className={`severity ${String(
                                                                                        finding.severity || "info"
                                                                                    ).toLowerCase()}`}
                                                                                >
                                                                                    {finding.severity}
                                                                                </span>

                                                                                <span>
                                                                                    {findingOpen ? "−" : "+"}
                                                                                </span>
                                                                            </div>
                                                                        </div>


                                                                        {/* FINDING DETAILS */}

                                                                        {findingOpen && (
                                                                            <div
                                                                                style={{
                                                                                    marginTop: "14px"
                                                                                }}
                                                                            >
                                                                                {finding.description && (
                                                                                    <p>
                                                                                        {finding.description}
                                                                                    </p>
                                                                                )}

                                                                                <div
                                                                                    style={{
                                                                                        marginTop: "16px"
                                                                                    }}
                                                                                >
                                                                                    <strong>
                                                                                        Affected locations
                                                                                    </strong>

                                                                                    <div
                                                                                        style={{
                                                                                            marginTop: "10px"
                                                                                        }}
                                                                                    >
                                                                                        {occurrences.length === 0 ? (
                                                                                            <p>
                                                                                                No occurrence details recorded.
                                                                                            </p>
                                                                                        ) : (
                                                                                            occurrences.map((occurrence) => (
                                                                                                <div
                                                                                                    key={occurrence.id}
                                                                                                    style={{
                                                                                                        padding: "10px 12px",
                                                                                                        marginBottom: "6px",
                                                                                                        borderRadius: "6px",
                                                                                                        background: "rgba(255,255,255,0.03)"
                                                                                                    }}
                                                                                                >
                                                                                                    <div>
                                                                                                        {occurrence.affected_module ||
                                                                                                            "Unknown location"}
                                                                                                    </div>

                                                                                                    {occurrence.parameter_name && (
                                                                                                        <div
                                                                                                            style={{
                                                                                                                marginTop: "4px",
                                                                                                                fontSize: "12px",
                                                                                                                opacity: 0.75
                                                                                                            }}
                                                                                                        >
                                                                                                            Parameter: {occurrence.parameter_name}
                                                                                                        </div>
                                                                                                    )}

                                                                                                    {occurrence.detected_vulnerability &&
                                                                                                        occurrence.detected_vulnerability !==
                                                                                                            finding.vulnerability && (
                                                                                                            <div
                                                                                                                style={{
                                                                                                                    marginTop: "4px",
                                                                                                                    fontSize: "12px",
                                                                                                                    opacity: 0.65
                                                                                                                }}
                                                                                                            >
                                                                                                                Detected as:{" "}
                                                                                                                {occurrence.detected_vulnerability}
                                                                                                            </div>
                                                                                                        )}
                                                                                                </div>
                                                                                            ))
                                                                                        )}
                                                                                    </div>
                                                                                </div>

                                                                                {finding.observed_result && (
                                                                                    <div
                                                                                        style={{
                                                                                            marginTop: "16px"
                                                                                        }}
                                                                                    >
                                                                                        <strong>
                                                                                            Observed result
                                                                                        </strong>

                                                                                        <p
                                                                                            style={{
                                                                                                whiteSpace: "pre-line"
                                                                                            }}
                                                                                        >
                                                                                            {finding.observed_result}
                                                                                        </p>
                                                                                    </div>
                                                                                )}

                                                                                {finding.impact && (
                                                                                    <div
                                                                                        style={{
                                                                                            marginTop: "16px"
                                                                                        }}
                                                                                    >
                                                                                        <strong>Impact</strong>

                                                                                        <p
                                                                                            style={{
                                                                                                whiteSpace: "pre-line"
                                                                                            }}
                                                                                        >
                                                                                            {finding.impact}
                                                                                        </p>
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })
                                )}
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
}

export default Findings;