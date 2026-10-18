import {
    useEffect,
    useState
} from "react";

import {
    FileSearch,
    Upload,
    RefreshCw,
    ExternalLink,
    ShieldCheck
} from "lucide-react";

import api from "../services/api";


// =========================================================
// FILE URL HELPER
// =========================================================

function getEvidenceUrl(filePath) {
    const baseUrl = (
        api.defaults.baseURL ||
        "http://localhost:5000/api"
    ).replace(/\/api\/?$/, "");

    const safePath = String(filePath || "")
        .replace(/\\/g, "/")
        .split("/")
        .filter(Boolean)
        .map(encodeURIComponent)
        .join("/");

    return `${baseUrl}/uploads/${safePath}`;
}


// =========================================================
// GROUP EVIDENCE BY FINDING
// =========================================================

function groupEvidenceByFinding(evidence) {
    const groups = new Map();

    for (const item of evidence) {
        const key = String(
            item.finding_id || "unknown"
        );

        if (!groups.has(key)) {
            groups.set(key, {
                finding_id: item.finding_id,
                vulnerability:
                    item.vulnerability ||
                    item.detected_vulnerability ||
                    "Unassigned finding",
                severity: item.severity || "Info",
                evidence: []
            });
        }

        groups.get(key).evidence.push(item);
    }

    return Array.from(groups.values());
}


// =========================================================
// EVIDENCE TABLE
// =========================================================

function EvidenceTable({ evidence }) {
    if (!evidence.length) {
        return (
            <div className="empty-large">
                <FileSearch size={30} />
                <p>No evidence records for this finding.</p>
            </div>
        );
    }

    return (
        <div className="table-container">
            <table className="data-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Occurrence / Location</th>
                        <th>Description</th>
                        <th>File</th>
                        <th>Created</th>
                    </tr>
                </thead>

                <tbody>
                    {evidence.map((item) => (
                        <tr key={item.id}>
                            <td>
                                {item.evidence_type}
                            </td>

                            <td>
                                <div>
                                    {item.affected_module ||
                                        item.description ||
                                        "-"}
                                </div>

                                {item.parameter_name && (
                                    <small>
                                        Parameter:{" "}
                                        {item.parameter_name}
                                    </small>
                                )}

                                {item.occurrence_id && (
                                    <small>
                                        Occurrence #{item.occurrence_id}
                                    </small>
                                )}
                            </td>

                            <td>
                                {item.description || "-"}
                            </td>

                            <td>
                                <a
                                    href={getEvidenceUrl(
                                        item.file_path
                                    )}
                                    target="_blank"
                                    rel="noreferrer"
                                >
                                    <ExternalLink
                                        size={14}
                                        style={{
                                            display: "inline",
                                            marginRight: "5px"
                                        }}
                                    />
                                    Open
                                </a>
                            </td>

                            <td>
                                {item.created_at
                                    ? new Date(
                                        item.created_at
                                    ).toLocaleString()
                                    : "-"}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}


// =========================================================
// MAIN EVIDENCE PAGE
// =========================================================

function Evidence() {
    const [assessments, setAssessments] = useState([]);
    const [findings, setFindings] = useState([]);

    const [selectedAssessment, setSelectedAssessment] =
        useState("");

    const [selectedFinding, setSelectedFinding] =
        useState("");

    const [scans, setScans] = useState([]);
    const [unassignedEvidence, setUnassignedEvidence] =
        useState([]);

    const [file, setFile] = useState(null);
    const [type, setType] = useState("Screenshot");
    const [description, setDescription] = useState("");

    const [loading, setLoading] = useState(false);
    const [uploading, setUploading] = useState(false);

    const [error, setError] = useState("");
    const [message, setMessage] = useState("");


// =========================================================
// LOAD EVIDENCE FOR EACH SCAN
// =========================================================

    const loadAssessmentEvidence = async (
        assessmentId,
        allFindings = findings
    ) => {
        if (!assessmentId) {
            setScans([]);
            setUnassignedEvidence([]);
            return;
        }

        setLoading(true);
        setError("");

        try {
            const scanResponse = await api.get(
                `/scans/${assessmentId}`
            );

            const scanList = Array.isArray(
                scanResponse.data
            )
                ? scanResponse.data
                : [];

            const scanGroups = await Promise.all(
                scanList.map(async (scan) => {
                    try {
                        const evidenceResponse =
                            await api.get(
                                `/evidence/scan/${scan.id}`
                            );

                        return {
                            ...scan,

                            evidence: Array.isArray(
                                evidenceResponse.data.evidence
                            )
                                ? evidenceResponse.data.evidence
                                : []
                        };
                    } catch (requestError) {
                        console.error(
                            "Unable to load evidence for scan",
                            scan.id,
                            requestError
                        );

                        return {
                            ...scan,
                            evidence: [],
                            evidenceError: true
                        };
                    }
                })
            );

            setScans(scanGroups);

            // Collect all finding IDs already displayed under scans.
            const scannedFindingIds = new Set();

            for (const scan of scanGroups) {
                for (const finding of (
                    scan.findings || []
                )) {
                    scannedFindingIds.add(
                        Number(finding.id)
                    );
                }
            }

            // Show old/manual findings that do not belong to a scan
            // in a separate section instead of mixing them into a scan.
            const legacyFindings = allFindings.filter(
                (finding) =>
                    Number(finding.assessment_id) ===
                        Number(assessmentId) &&
                    !scannedFindingIds.has(
                        Number(finding.id)
                    )
            );

            const legacyGroups = await Promise.all(
                legacyFindings.map(async (finding) => {
                    try {
                        const evidenceResponse =
                            await api.get(
                                `/evidence/${finding.id}`
                            );

                        const evidence = Array.isArray(
                            evidenceResponse.data
                        )
                            ? evidenceResponse.data.filter(
                                (item) => !item.scan_id
                            )
                            : [];

                        return {
                            finding_id: finding.id,
                            vulnerability:
                                finding.vulnerability,
                            evidence
                        };
                    } catch {
                        return {
                            finding_id: finding.id,
                            vulnerability:
                                finding.vulnerability,
                            evidence: []
                        };
                    }
                })
            );

            setUnassignedEvidence(
                legacyGroups.filter(
                    (group) => group.evidence.length > 0
                )
            );
        } catch (requestError) {
            console.error(
                "Failed to load scan evidence:",
                requestError
            );

            setError(
                requestError.response?.data?.error ||
                "Failed to load scan history and evidence."
            );

            setScans([]);
            setUnassignedEvidence([]);
        } finally {
            setLoading(false);
        }
    };


// =========================================================
// INITIAL LOAD
// =========================================================

    useEffect(() => {
        let cancelled = false;

        const initialize = async () => {
            setLoading(true);
            setError("");

            try {
                const [
                    assessmentResponse,
                    findingResponse
                ] = await Promise.all([
                    api.get("/assessments"),
                    api.get("/findings")
                ]);

                if (cancelled) {
                    return;
                }

                const assessmentList =
                    Array.isArray(assessmentResponse.data)
                        ? assessmentResponse.data
                        : [];

                const findingList =
                    Array.isArray(findingResponse.data)
                        ? findingResponse.data
                        : [];

                setAssessments(assessmentList);
                setFindings(findingList);

                if (assessmentList.length > 0) {
                    const firstId = String(
                        assessmentList[0].id
                    );

                    setSelectedAssessment(firstId);

                    await loadAssessmentEvidence(
                        firstId,
                        findingList
                    );
                } else {
                    setScans([]);
                    setUnassignedEvidence([]);
                }
            } catch (requestError) {
                if (!cancelled) {
                    setError(
                        requestError.response?.data?.error ||
                        "Failed to initialize the Evidence page."
                    );
                }
            } finally {
                if (!cancelled) {
                    setLoading(false);
                }
            }
        };

        initialize();

        return () => {
            cancelled = true;
        };
    }, []);


// =========================================================
// ASSESSMENT CHANGE
// =========================================================

    const handleAssessmentChange = async (event) => {
        const assessmentId = event.target.value;

        setSelectedAssessment(assessmentId);
        setSelectedFinding("");
        setMessage("");
        setError("");

        await loadAssessmentEvidence(
            assessmentId,
            findings
        );
    };


// =========================================================
// FINDINGS AVAILABLE FOR MANUAL EVIDENCE
// =========================================================

    const selectedAssessmentFindings =
        findings.filter(
            (finding) =>
                Number(finding.assessment_id) ===
                Number(selectedAssessment)
        );


// =========================================================
// MANUAL EVIDENCE UPLOAD
// =========================================================

    const uploadEvidence = async (event) => {
        event.preventDefault();

        setError("");
        setMessage("");

        if (!selectedFinding || !file) {
            setError(
                "Select a finding and an evidence file."
            );
            return;
        }

        const formData = new FormData();

        formData.append("evidence", file);
        formData.append("evidence_type", type);
        formData.append("description", description);

        setUploading(true);

        try {
            await api.post(
                `/evidence/${selectedFinding}`,
                formData,
                {
                    headers: {
                        "Content-Type": "multipart/form-data"
                    }
                }
            );

            setMessage(
                "Evidence uploaded and linked to its finding and scan."
            );

            setFile(null);
            setDescription("");

            await loadAssessmentEvidence(
                selectedAssessment,
                findings
            );
        } catch (requestError) {
            console.error(
                "Evidence upload failed:",
                requestError
            );

            setError(
                requestError.response?.data?.error ||
                "Evidence upload failed."
            );
        } finally {
            setUploading(false);
        }
    };


// =========================================================
// SCAN GROUP RENDERING
// =========================================================

    const renderScan = (scan, index) => {
        const evidenceGroups =
            groupEvidenceByFinding(scan.evidence || []);

        const findingCount =
            (scan.findings || []).length;

        return (
            <details
                className="panel"
                key={scan.id}
                open={index === 0}
                style={{ marginBottom: "16px" }}
            >
                <summary
                    style={{
                        cursor: "pointer",
                        padding: "4px",
                        listStylePosition: "inside"
                    }}
                >
                    <strong>
                        Scan #{scan.scan_number}
                    </strong>

                    <span
                        style={{
                            marginLeft: "12px",
                            color: "#9eb6ce",
                            fontSize: "12px"
                        }}
                    >
                        {scan.pages_scanned || 0} pages
                        {" • "}
                        {findingCount} categories
                        {" • "}
                        {evidenceGroups.reduce(
                            (count, group) =>
                                count + group.evidence.length,
                            0
                        )} evidence records
                    </span>

                    <span
                        style={{
                            float: "right",
                            fontSize: "11px"
                        }}
                    >
                        {scan.status}
                    </span>
                </summary>

                <div style={{ marginTop: "18px" }}>
                    {scan.evidenceError && (
                        <p>
                            Some evidence records could not
                            be loaded for this scan.
                        </p>
                    )}

                    {!scan.evidenceError &&
                        evidenceGroups.length === 0 && (
                            <div className="empty-large">
                                <FileSearch size={30} />

                                <p>
                                    No evidence records for this scan.
                                </p>

                                <small>
                                    A new scan using automatic
                                    evidence collection will create
                                    evidence records for detected
                                    occurrences.
                                </small>
                            </div>
                        )}

                    {evidenceGroups.map((group) => (
                        <div
                            key={group.finding_id}
                            style={{
                                marginTop: "18px"
                            }}
                        >
                            <div
                                style={{
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "space-between",
                                    gap: "12px",
                                    marginBottom: "10px"
                                }}
                            >
                                <div>
                                    <h3>
                                        {group.vulnerability}
                                    </h3>

                                    <small>
                                        Finding #{group.finding_id}
                                    </small>
                                </div>

                                <span>
                                    {group.evidence.length} records
                                </span>
                            </div>

                            <EvidenceTable
                                evidence={group.evidence}
                            />
                        </div>
                    ))}
                </div>
            </details>
        );
    };


// =========================================================
// PAGE UI
// =========================================================

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        EVIDENCE MANAGEMENT
                    </p>

                    <h2>Security Evidence</h2>

                    <p>
                        Browse evidence by assessment,
                        scan and finding. Manual uploads
                        remain available.
                    </p>
                </div>
            </div>

            {message && (
                <div className="panel">
                    <ShieldCheck
                        size={17}
                        style={{
                            display: "inline",
                            marginRight: "8px"
                        }}
                    />
                    {message}
                </div>
            )}

            {error && (
                <div className="panel">
                    <p>{error}</p>
                </div>
            )}


            {/* ASSESSMENT FILTER */}

            <div className="panel">
                <div className="panel-header">
                    <div>
                        <h3>Evidence by Assessment</h3>

                        <p>
                            Choose an assessment to see
                            each scan's evidence separately.
                        </p>
                    </div>

                    <button
                        type="button"
                        className="secondary-btn"
                        disabled={loading || !selectedAssessment}
                        onClick={() =>
                            loadAssessmentEvidence(
                                selectedAssessment,
                                findings
                            )
                        }
                    >
                        <RefreshCw size={15} />
                        Refresh
                    </button>
                </div>

                <select
                    value={selectedAssessment}
                    onChange={handleAssessmentChange}
                    disabled={loading}
                    style={{
                        width: "100%",
                        maxWidth: "520px"
                    }}
                >
                    <option value="">
                        Select assessment
                    </option>

                    {assessments.map((assessment) => (
                        <option
                            key={assessment.id}
                            value={assessment.id}
                        >
                            {assessment.title}
                            {" — "}
                            {assessment.target_url}
                        </option>
                    ))}
                </select>
            </div>


            {/* MANUAL UPLOAD */}

            <div className="panel">
                <h3>Upload Additional Evidence</h3>

                <p>
                    Upload a screenshot, HTTP data or other
                    supporting file for a finding.
                </p>

                <form
                    onSubmit={uploadEvidence}
                    className="form-grid"
                >
                    <select
                        value={selectedFinding}
                        onChange={(event) =>
                            setSelectedFinding(
                                event.target.value
                            )
                        }
                        required
                    >
                        <option value="">
                            Select finding
                        </option>

                        {selectedAssessmentFindings.map(
                            (finding) => (
                                <option
                                    key={finding.id}
                                    value={finding.id}
                                >
                                    #{finding.id}
                                    {" — "}
                                    {finding.vulnerability}
                                </option>
                            )
                        )}
                    </select>

                    <select
                        value={type}
                        onChange={(event) =>
                            setType(event.target.value)
                        }
                    >
                        <option>Screenshot</option>
                        <option>HTTP Request</option>
                        <option>HTTP Response</option>
                        <option>Scan Result</option>
                        <option>Other</option>
                    </select>

                    <input
                        type="file"
                        accept=".png,.jpg,.jpeg,.pdf,.txt"
                        onChange={(event) =>
                            setFile(
                                event.target.files?.[0] || null
                            )
                        }
                        required
                    />

                    <textarea
                        placeholder="Evidence description"
                        value={description}
                        onChange={(event) =>
                            setDescription(event.target.value)
                        }
                        rows="3"
                    />

                    <button
                        className="primary-btn"
                        type="submit"
                        disabled={uploading}
                    >
                        <Upload size={17} />

                        {uploading
                            ? "Uploading..."
                            : "Upload Evidence"}
                    </button>
                </form>
            </div>


            {/* SCAN-BY-SCAN EVIDENCE */}

            <div className="panel">
                <div className="panel-header">
                    <div>
                        <h3>Scan Evidence History</h3>

                        <p>
                            Every scan is displayed as a separate
                            section with its own findings and
                            evidence records.
                        </p>
                    </div>
                </div>

                {loading ? (
                    <div className="empty-large">
                        Loading scan evidence...
                    </div>
                ) : !selectedAssessment ? (
                    <div className="empty-large">
                        Select an assessment to continue.
                    </div>
                ) : scans.length === 0 ? (
                    <div className="empty-large">
                        <FileSearch size={36} />

                        <p>
                            No scans recorded for this assessment.
                        </p>
                    </div>
                ) : (
                    scans.map(renderScan)
                )}
            </div>


            {/* LEGACY / UNASSIGNED EVIDENCE */}

            {unassignedEvidence.length > 0 && (
                <div className="panel">
                    <h3>Evidence Not Linked to a Scan</h3>

                    <p>
                        These records belong to legacy findings
                        without a scan record. They are kept
                        separate and have not been discarded.
                    </p>

                    {unassignedEvidence.map((group) => (
                        <div
                            key={group.finding_id}
                            style={{ marginTop: "18px" }}
                        >
                            <h3>
                                {group.vulnerability}
                                {" — Finding #"}
                                {group.finding_id}
                            </h3>

                            <EvidenceTable
                                evidence={group.evidence}
                            />
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

export default Evidence;