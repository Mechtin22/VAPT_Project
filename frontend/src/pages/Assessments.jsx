import { useEffect, useState } from "react";

import {
    Plus,
    ShieldCheck,
    X,
    Play,
    Loader2,
    Trash2,
    RefreshCw
} from "lucide-react";

import api from "../services/api";

function Assessments() {
    const [assessments, setAssessments] = useState([]);
    const [showForm, setShowForm] = useState(false);

    const [form, setForm] = useState({
        title: "",
        target_url: "http://localhost/DVWA",
        scope_description: "",
        tester: ""
    });

    const [loading, setLoading] = useState(true);
    const [scanningId, setScanningId] = useState(null);
    const [deletingId, setDeletingId] = useState(null);

    const [scanResult, setScanResult] = useState(null);
    const [notice, setNotice] = useState(null);

    // =====================================================
    // DVWA SECURITY LEVEL
    // =====================================================

    const [scanSecurityLevel, setScanSecurityLevel] =
        useState("low");

    const securityLevels = [
        {
            value: "low",
            label: "Low"
        },
        {
            value: "medium",
            label: "Medium"
        },
        {
            value: "high",
            label: "High"
        },
        {
            value: "impossible",
            label: "Impossible"
        }
    ];

    // =====================================================
    // LOAD ASSESSMENTS
    // =====================================================

    const loadAssessments = async (showLoading = false) => {
        if (showLoading) {
            setLoading(true);
        }

        try {
            const response = await api.get("/assessments");

            setAssessments(
                Array.isArray(response.data)
                    ? response.data
                    : []
            );

            return true;
        } catch (error) {
            console.error(
                "Failed to load assessments:",
                error
            );

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    "Failed to load assessments."
            });

            return false;
        } finally {
            if (showLoading) {
                setLoading(false);
            }
        }
    };

    useEffect(() => {
        loadAssessments(true);

        // Initial load only.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // =====================================================
    // GET DISPLAY ASSESSMENT NUMBER
    // =====================================================
    // The API returns assessments ordered newest first.
    // Reverse the list position to number them chronologically:
    // oldest = #1, newest = #N.
    //
    // This is a display number only. It never replaces the
    // database ID used by scans, findings, or API requests.
    // =====================================================

    const getAssessmentNumber = (assessmentId) => {
        const index = assessments.findIndex(
            (assessment) => assessment.id === assessmentId
        );

        if (index === -1) {
            return assessmentId;
        }

        return assessments.length - index;
    };

    // =====================================================
    // FORM CHANGE
    // =====================================================

    const handleChange = (event) => {
        setForm((previous) => ({
            ...previous,
            [event.target.name]: event.target.value
        }));
    };

    // =====================================================
    // CREATE ASSESSMENT
    // =====================================================

    const createAssessment = async (event) => {
        event.preventDefault();
        setNotice(null);

        try {
            await api.post("/assessments", form);

            setForm({
                title: "",
                target_url: "http://localhost/DVWA",
                scope_description: "",
                tester: ""
            });

            setShowForm(false);

            await loadAssessments(false);

            setNotice({
                type: "success",
                message: "Assessment created successfully."
            });
        } catch (error) {
            console.error(
                "Failed to create assessment:",
                error
            );

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    "Failed to create assessment."
            });
        }
    };

    // =====================================================
    // RUN AUTOMATED SCAN
    // Pass the selected security level to the backend.
    // =====================================================

    const runScan = async (assessment) => {
        const selectedLevel = scanSecurityLevel;

        const confirmed = window.confirm(
            `Run the automated security scan?\n\n` +
            `Assessment: ${assessment.title}\n` +
            `Target: ${assessment.target_url}\n` +
            `DVWA security level: ${selectedLevel.toUpperCase()}\n\n` +
            "The scanner will use its own authenticated DVWA session."
        );

        if (!confirmed) {
            return;
        }

        setScanningId(assessment.id);
        setScanResult(null);
        setNotice(null);

        try {
            const response = await api.post(
                `/scans/${assessment.id}`,
                {
                    security_level: selectedLevel
                }
            );

            const result = response.data;

            // Do not display an apparently successful result if
            // the backend says the requested security level differs.
            if (
                result.security_level &&
                result.security_level !== selectedLevel
            ) {
                throw new Error(
                    `Security-level mismatch. Selected ${selectedLevel}, ` +
                    `but the backend returned ${result.security_level}.`
                );
            }

            setScanResult(result);

            await loadAssessments(false);

            if (
                result.security_level_verified === false
            ) {
                setNotice({
                    type: "warning",
                    message:
                        "The scan response did not confirm the active DVWA security level. " +
                        "Review the backend logs before relying on the results."
                });
            } else {
                setNotice({
                    type: "success",
                    message:
                        `Scan #${result.scan_number} completed. ` +
                        `Selected DVWA security level: ` +
                        `${String(
                            result.security_level || selectedLevel
                        ).toUpperCase()}.`
                });
            }
        } catch (error) {
            console.error("Scan error:", error);

            setNotice({
                type: "error",
                message:
                    error.response?.data?.error ||
                    error.response?.data?.message ||
                    error.message ||
                    "Scan failed."
            });
        } finally {
            setScanningId(null);
        }
    };

    // =====================================================
    // DELETE ASSESSMENT
    // =====================================================

    const deleteAssessment = async (assessment) => {
        const assessmentNumber = getAssessmentNumber(
            assessment.id
        );

        const confirmed = window.confirm(
            `Permanently delete Assessment #${assessmentNumber}: ` +
            `"${assessment.title}"?\n\n` +
            "This deletes its scans, findings, occurrences, " +
            "evidence records/files, retests and HTTP requests. " +
            "This cannot be undone."
        );

        if (!confirmed) {
            return;
        }

        const typed = window.prompt(
            `Type DELETE exactly to remove:\n${assessment.title}`
        );

        if (typed !== "DELETE") {
            setNotice({
                type: "info",
                message: "Assessment deletion was cancelled."
            });

            return;
        }

        setDeletingId(assessment.id);
        setNotice(null);

        try {
            // Always use the real database ID for the API request.
            const response = await api.delete(
                `/assessments/${assessment.id}`
            );

            const data = response.data || {};

            setScanResult((previous) =>
                previous?.assessment_id === assessment.id
                    ? null
                    : previous
            );

            // Reload the list. Display numbers automatically
            // recalculate from the updated assessment list.
            await loadAssessments(false);

            const lines = [
                data.message || "Assessment deleted.",
                `Scans: ${data.deleted_scans ?? 0}`,
                `Findings: ${data.deleted_findings ?? 0}`,
                `Occurrences: ${data.deleted_occurrences ?? 0}`,
                `Evidence records: ${data.deleted_evidence_records ?? 0}`,
                `Retests: ${data.deleted_retests ?? 0}`,
                `HTTP requests: ${data.deleted_http_requests ?? 0}`,
                `Automatic evidence files: ${data.deleted_automatic_evidence_files ?? 0}`,
                `Manual upload files: ${data.deleted_manual_upload_files ?? 0}`
            ];

            if (data.file_cleanup_warnings?.length) {
                lines.push(
                    `File cleanup warnings: ${data.file_cleanup_warnings.length}`
                );
            }

            setNotice({
                type: data.file_cleanup_warnings?.length
                    ? "warning"
                    : "success",
                message: lines.join("\n"),
                warnings: data.file_cleanup_warnings || []
            });
        } catch (error) {
            console.error(
                "Assessment deletion failed:",
                error
            );

            setNotice({
                type:
                    error.response?.status === 409
                        ? "warning"
                        : "error",
                message:
                    error.response?.data?.error ||
                    error.response?.data?.message ||
                    "Failed to delete assessment."
            });
        } finally {
            setDeletingId(null);
        }
    };

    // =====================================================
    // RENDER
    // =====================================================

    return (
        <div>
            {/* PAGE HEADER */}

            <div className="page-header">
                <div>
                    <p className="eyebrow">ASSESSMENTS</p>
                    <h2>Security Assessments</h2>
                    <p>
                        Manage authorized DVWA testing engagements.
                    </p>
                </div>

                <div
                    style={{
                        display: "flex",
                        gap: "10px",
                        flexWrap: "wrap"
                    }}
                >
                    <button
                        type="button"
                        className="secondary-btn"
                        onClick={() => loadAssessments(false)}
                        disabled={
                            loading ||
                            scanningId !== null ||
                            deletingId !== null
                        }
                    >
                        <RefreshCw size={16} />
                        Refresh
                    </button>

                    <button
                        type="button"
                        className="primary-btn"
                        onClick={() => setShowForm(true)}
                    >
                        <Plus size={18} />
                        New Assessment
                    </button>
                </div>
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
                                    : notice.type === "info"
                                        ? "#0284c7"
                                        : "#dc2626"
                        }`
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            gap: "16px"
                        }}
                    >
                        <div>
                            <strong>
                                {notice.type === "success"
                                    ? "Completed"
                                    : notice.type === "warning"
                                        ? "Completed with warnings"
                                        : notice.type === "info"
                                            ? "Information"
                                            : "Notice"}
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
                                    {notice.warnings.map(
                                        (warning, index) => (
                                            <li
                                                key={`${
                                                    warning.scan_id ||
                                                    warning.file_path ||
                                                    index
                                                }-${index}`}
                                            >
                                                {warning.file_path ||
                                                    warning.scan_id ||
                                                    warning.evidence_id ||
                                                    ""}
                                                {": "}
                                                {warning.message}
                                            </li>
                                        )
                                    )}
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

            {/* DVWA SECURITY LEVEL SELECTOR */}

            <div className="panel">
                <div className="panel-header">
                    <div>
                        <h3>DVWA Security Level</h3>
                        <p>
                            Choose the level the scanner should use
                            for its next scan.
                        </p>
                    </div>
                </div>

                <div
                    style={{
                        display: "grid",
                        gridTemplateColumns:
                            "repeat(auto-fit, minmax(220px, 1fr))",
                        gap: "16px",
                        alignItems: "end"
                    }}
                >
                    <div>
                        <label
                            htmlFor="scan-security-level"
                            style={{
                                display: "block",
                                marginBottom: "8px",
                                fontWeight: 600
                            }}
                        >
                            Security level for new scans
                        </label>

                        <select
                            id="scan-security-level"
                            name="scan_security_level"
                            value={scanSecurityLevel}
                            onChange={(event) =>
                                setScanSecurityLevel(
                                    event.target.value
                                )
                            }
                            disabled={
                                scanningId !== null ||
                                deletingId !== null
                            }
                            style={{
                                width: "100%",
                                padding: "10px 12px",
                                border: "1px solid #d1d5db",
                                borderRadius: "7px",
                                background: "var(--input-bg, #ffffff)",
                                color: "var(--text-color, #111827)",
                                fontSize: "14px"
                            }}
                        >
                            {securityLevels.map((level) => (
                                <option
                                    key={level.value}
                                    value={level.value}
                                >
                                    {level.label}
                                </option>
                            ))}
                        </select>
                    </div>

                    <div>
                        <p
                            style={{
                                margin: 0,
                                lineHeight: 1.6
                            }}
                        >
                            Selected level:{" "}
                            <strong>
                                {scanSecurityLevel.toUpperCase()}
                            </strong>
                        </p>
                    </div>
                </div>

                <p
                    style={{
                        marginTop: "14px",
                        fontSize: "13px",
                        lineHeight: 1.6
                    }}
                >
                    The scanner uses a separate authenticated DVWA
                    session. Changing the security level in your
                    browser's DVWA tab does not automatically change
                    the scanner's session. The scan API applies the
                    level selected here.
                </p>
            </div>

            {/* CREATE ASSESSMENT */}

            {showForm && (
                <div className="panel">
                    <div className="panel-header">
                        <div>
                            <h3>Create Assessment</h3>
                            <p>
                                Register a new authorized DVWA test.
                            </p>
                        </div>

                        <button
                            type="button"
                            className="secondary-btn"
                            onClick={() => setShowForm(false)}
                        >
                            <X size={16} />
                            Close
                        </button>
                    </div>

                    <form
                        onSubmit={createAssessment}
                        className="form-grid"
                    >
                        <input
                            name="title"
                            placeholder="Assessment title"
                            value={form.title}
                            onChange={handleChange}
                            required
                        />

                        <input
                            name="target_url"
                            placeholder="DVWA target URL"
                            value={form.target_url}
                            onChange={handleChange}
                            required
                        />

                        <input
                            name="tester"
                            placeholder="Tester name"
                            value={form.tester}
                            onChange={handleChange}
                        />

                        <textarea
                            name="scope_description"
                            placeholder="Scope description"
                            value={form.scope_description}
                            onChange={handleChange}
                            rows="4"
                        />

                        <button
                            className="primary-btn"
                            type="submit"
                            disabled={
                                scanningId !== null ||
                                deletingId !== null
                            }
                        >
                            Create Assessment
                        </button>
                    </form>
                </div>
            )}

            {/* SCAN RESULT */}

            {scanResult && (
                <div className="panel">
                    <div className="panel-header">
                        <div>
                            <p className="eyebrow">SCAN RESULTS</p>

                            <h3>
                                Scan #{scanResult.scan_number} Completed
                            </h3>

                            <p>
                                The automated scanner finished. Validate
                                detections before treating them as confirmed
                                vulnerabilities.
                            </p>
                        </div>

                        <button
                            type="button"
                            className="secondary-btn"
                            onClick={() => setScanResult(null)}
                        >
                            Close
                        </button>
                    </div>

                    {/* SELECTED AND VERIFIED SECURITY LEVEL */}

                    <div
                        className="panel"
                        style={{
                            margin: "0 0 20px",
                            padding: "14px 16px"
                        }}
                    >
                        <strong>DVWA Security Level Used</strong>

                        <div
                            style={{
                                display: "flex",
                                flexWrap: "wrap",
                                alignItems: "center",
                                gap: "12px",
                                marginTop: "8px"
                            }}
                        >
                            <span
                                className="badge blue"
                                style={{
                                    textTransform: "uppercase"
                                }}
                            >
                                {scanResult.security_level || "Unknown"}
                            </span>

                            <span>
                                {scanResult.security_level_verified === true
                                    ? "Level verified by the scanner"
                                    : "Verification not confirmed in the response"}
                            </span>
                        </div>
                    </div>

                    {/* SCAN METRICS */}

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns:
                                "repeat(auto-fit, minmax(160px, 1fr))",
                            gap: "12px",
                            marginBottom: "20px"
                        }}
                    >
                        {[
                            [
                                "Pages Scanned",
                                scanResult.pages_scanned ?? 0
                            ],
                            [
                                "Observations",
                                scanResult.findings_detected ?? 0
                            ],
                            [
                                "Findings Created",
                                scanResult.findings_created ?? 0
                            ],
                            [
                                "Evidence Records",
                                scanResult.automatic_evidence_created ?? 0
                            ],
                            [
                                "Duration",
                                scanResult.duration_ms
                                    ? `${(
                                        scanResult.duration_ms / 1000
                                    ).toFixed(2)}s`
                                    : "0s"
                            ]
                        ].map(([label, value]) => (
                            <div
                                className="panel"
                                key={label}
                                style={{
                                    margin: 0,
                                    padding: "14px"
                                }}
                            >
                                <strong>{label}</strong>

                                <div
                                    style={{
                                        fontSize: "24px",
                                        fontWeight: 700,
                                        marginTop: "6px"
                                    }}
                                >
                                    {value}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* FINDINGS TABLE */}

                    {Array.isArray(scanResult.findings) &&
                    scanResult.findings.length > 0 ? (
                        <div className="table-container">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Vulnerability</th>
                                        <th>Affected Locations</th>
                                        <th>Occurrences</th>
                                        <th>Severity</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {scanResult.findings.map((finding) => (
                                        <tr key={finding.id}>
                                            <td>
                                                <strong>
                                                    {finding.vulnerability}
                                                </strong>
                                            </td>

                                            <td>
                                                {finding.affected_module}
                                            </td>

                                            <td>
                                                {finding.occurrence_count ?? 0}
                                            </td>

                                            <td>
                                                <span
                                                    className={`severity ${String(
                                                        finding.severity ||
                                                        "info"
                                                    ).toLowerCase()}`}
                                                >
                                                    {finding.severity}
                                                </span>
                                            </td>

                                            <td>{finding.status}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="empty-state">
                            No vulnerabilities were detected by the
                            current scanner checks.
                        </div>
                    )}
                </div>
            )}

            {/* ASSESSMENT CARDS */}

            {loading ? (
                <div className="panel">
                    Loading assessments...
                </div>
            ) : (
                <div className="assessment-grid">
                    {assessments.map((assessment, index) => {
                        const busy =
                            scanningId === assessment.id ||
                            deletingId === assessment.id;

                        // The API sorts newest assessments first.
                        // Reverse the index so the oldest is #1.
                        // This value is only for display.
                        const assessmentNumber =
                            assessments.length - index;

                        return (
                            <div
                                className="assessment-card"
                                key={assessment.id}
                            >
                                <div className="assessment-icon">
                                    <ShieldCheck size={24} />
                                </div>

                                <p className="eyebrow">
                                    ASSESSMENT #{assessmentNumber}
                                </p>

                                <h3>{assessment.title}</h3>
                                <p>{assessment.target_url}</p>

                                <span className="badge blue">
                                    {assessment.status}
                                </span>

                                <button
                                    className="primary-btn"
                                    type="button"
                                    disabled={
                                        busy ||
                                        scanningId !== null ||
                                        deletingId !== null
                                    }
                                    onClick={() => runScan(assessment)}
                                    style={{
                                        marginTop: "14px",
                                        width: "100%"
                                    }}
                                >
                                    {scanningId === assessment.id ? (
                                        <>
                                            <Loader2
                                                size={16}
                                                className="scan-spinner"
                                            />
                                            Scanning...
                                        </>
                                    ) : (
                                        <>
                                            <Play size={16} />
                                            Run Scan
                                        </>
                                    )}
                                </button>

                                <button
                                    type="button"
                                    disabled={
                                        busy ||
                                        scanningId !== null ||
                                        deletingId !== null
                                    }
                                    onClick={() =>
                                        deleteAssessment(assessment)
                                    }
                                    style={{
                                        marginTop: "8px",
                                        width: "100%",
                                        padding: "10px 12px",
                                        display: "inline-flex",
                                        justifyContent: "center",
                                        alignItems: "center",
                                        gap: "8px",
                                        background: "#7f1d1d",
                                        color: "#ffffff",
                                        border: "1px solid #991b1b",
                                        borderRadius: "7px",
                                        cursor: busy
                                            ? "not-allowed"
                                            : "pointer",
                                        opacity: busy ? 0.6 : 1
                                    }}
                                >
                                    <Trash2 size={16} />

                                    {deletingId === assessment.id
                                        ? "Deleting Assessment..."
                                        : "Delete Assessment"}
                                </button>
                            </div>
                        );
                    })}

                    {assessments.length === 0 && (
                        <div className="panel">
                            No assessments created yet.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default Assessments;