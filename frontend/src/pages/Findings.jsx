import {
    useEffect,
    useState
} from "react";

import api from "../services/api";


function Findings() {
    const [
        assessments,
        setAssessments
    ] = useState([]);


    const [
        scanHistory,
        setScanHistory
    ] = useState({});


    const [
        expandedAssessments,
        setExpandedAssessments
    ] = useState({});


    const [
        expandedScans,
        setExpandedScans
    ] = useState({});


    const [
        expandedFindings,
        setExpandedFindings
    ] = useState({});


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        clearingId,
        setClearingId
    ] = useState(null);


    // =====================================================
    // LOAD ASSESSMENTS
    // =====================================================

    const loadAssessments =
        async () => {
            try {
                setLoading(true);

                const response =
                    await api.get(
                        "/assessments"
                    );

                setAssessments(
                    response.data
                );


                const history = {};


                for (
                    const assessment
                    of response.data
                ) {
                    try {
                        const scanResponse =
                            await api.get(
                                `/scans/${assessment.id}`
                            );

                        history[
                            assessment.id
                        ] =
                            scanResponse.data;

                    } catch (error) {
                        console.error(
                            `Failed to load scans for assessment ${assessment.id}`,
                            error
                        );

                        history[
                            assessment.id
                        ] = [];
                    }
                }


                setScanHistory(
                    history
                );

            } catch (error) {
                console.error(
                    "Failed to load findings:",
                    error
                );

            } finally {
                setLoading(false);
            }
        };


    useEffect(() => {
        loadAssessments();
    }, []);


    // =====================================================
    // TOGGLES
    // =====================================================

    const toggleAssessment =
        (id) => {
            setExpandedAssessments(
                (previous) => ({
                    ...previous,

                    [id]:
                        !previous[id]
                })
            );
        };


    const toggleScan =
        (id) => {
            setExpandedScans(
                (previous) => ({
                    ...previous,

                    [id]:
                        !previous[id]
                })
            );
        };


    const toggleFinding =
        (id) => {
            setExpandedFindings(
                (previous) => ({
                    ...previous,

                    [id]:
                        !previous[id]
                })
            );
        };


    // =====================================================
    // CLEAR HISTORY
    // =====================================================

    const clearHistory =
        async (
            assessment
        ) => {
            const confirmed =
                window.confirm(
                    `Clear all scan history and scanner findings for "${assessment.title}"?\n\nThis cannot be undone.`
                );


            if (!confirmed) {
                return;
            }


            try {
                setClearingId(
                    assessment.id
                );


                await api.delete(
                    `/scans/${assessment.id}/history`
                );


                await loadAssessments();


                alert(
                    "Scan history cleared successfully."
                );

            } catch (error) {
                console.error(
                    error
                );


                alert(
                    error.response?.data?.error ||
                    "Failed to clear scan history."
                );

            } finally {
                setClearingId(
                    null
                );
            }
        };


    // =====================================================
    // RENDER
    // =====================================================

    return (
        <div>

            {/* =================================================
                PAGE HEADER
            ================================================= */}

            <div className="page-header">

                <div>

                    <p className="eyebrow">
                        VULNERABILITY MANAGEMENT
                    </p>

                    <h2>
                        Scan Findings
                    </h2>

                    <p>
                        Findings are organized by
                        assessment, scan and
                        vulnerability category.
                    </p>

                </div>

            </div>


            {/* =================================================
                LOADING
            ================================================= */}

            {loading && (
                <div className="panel">
                    Loading scan history...
                </div>
            )}


            {/* =================================================
                NO ASSESSMENTS
            ================================================= */}

            {!loading &&
                assessments.length === 0 && (
                    <div className="panel">
                        No assessments found.
                    </div>
                )}


            {/* =================================================
                ASSESSMENTS
            ================================================= */}

            {!loading &&
                assessments.map(
                    (assessment) => {

                        const scans =
                            scanHistory[
                                assessment.id
                            ] || [];


                        const assessmentOpen =
                            !!expandedAssessments[
                                assessment.id
                            ];


                        return (
                            <div
                                className="panel"
                                key={
                                    assessment.id
                                }
                                style={{
                                    marginBottom:
                                        "20px"
                                }}
                            >

                                {/* =================================
                                    ASSESSMENT HEADER
                                ================================= */}

                                <div
                                    style={{
                                        display:
                                            "flex",

                                        justifyContent:
                                            "space-between",

                                        alignItems:
                                            "center",

                                        gap:
                                            "20px",

                                        cursor:
                                            "pointer"
                                    }}

                                    onClick={() =>
                                        toggleAssessment(
                                            assessment.id
                                        )
                                    }
                                >

                                    <div>

                                        <p className="eyebrow">
                                            ASSESSMENT
                                            #
                                            {
                                                assessment.id
                                            }
                                        </p>

                                        <h3>
                                            {
                                                assessment.title
                                            }
                                        </h3>

                                        <p>
                                            {
                                                assessment.target_url
                                            }
                                        </p>

                                    </div>


                                    <div
                                        style={{
                                            display:
                                                "flex",

                                            alignItems:
                                                "center",

                                            gap:
                                                "10px"
                                        }}
                                    >

                                        <span
                                            className="severity"
                                        >
                                            {
                                                scans.length
                                            }
                                            {" "}
                                            scan
                                            {scans.length ===
                                            1
                                                ? ""
                                                : "s"}
                                        </span>


                                        <button
                                            type="button"

                                            onClick={(
                                                event
                                            ) => {
                                                event.stopPropagation();

                                                clearHistory(
                                                    assessment
                                                );
                                            }}

                                            disabled={
                                                clearingId ===
                                                assessment.id
                                            }
                                        >
                                            {clearingId ===
                                            assessment.id
                                                ? "Clearing..."
                                                : "Clear History"}
                                        </button>


                                        <span
                                            style={{
                                                fontSize:
                                                    "22px"
                                            }}
                                        >
                                            {
                                                assessmentOpen
                                                    ? "−"
                                                    : "+"
                                            }
                                        </span>

                                    </div>

                                </div>


                                {/* =================================
                                    ASSESSMENT CONTENT
                                ================================= */}

                                {assessmentOpen && (

                                    <div
                                        style={{
                                            marginTop:
                                                "20px"
                                        }}
                                    >

                                        {scans.length ===
                                        0 ? (

                                            <div className="empty-state">
                                                No scans have
                                                been run for
                                                this assessment.
                                            </div>

                                        ) : (

                                            scans.map(
                                                (
                                                    scan
                                                ) => {

                                                    const scanOpen =
                                                        !!expandedScans[
                                                            scan.id
                                                        ];


                                                    return (
                                                        <div
                                                            key={
                                                                scan.id
                                                            }
                                                            style={{
                                                                border:
                                                                    "1px solid rgba(255,255,255,0.08)",

                                                                borderRadius:
                                                                    "10px",

                                                                marginBottom:
                                                                    "14px",

                                                                overflow:
                                                                    "hidden"
                                                            }}
                                                        >

                                                            {/* =============================
                                                                SCAN HEADER
                                                            ============================= */}

                                                            <div
                                                                style={{
                                                                    display:
                                                                        "flex",

                                                                    justifyContent:
                                                                        "space-between",

                                                                    alignItems:
                                                                        "center",

                                                                    padding:
                                                                        "16px 18px",

                                                                    cursor:
                                                                        "pointer"
                                                                }}

                                                                onClick={() =>
                                                                    toggleScan(
                                                                        scan.id
                                                                    )
                                                                }
                                                            >

                                                                <div>

                                                                    <strong>
                                                                        Scan #
                                                                        {
                                                                            scan.scan_number
                                                                        }
                                                                    </strong>

                                                                    <div
                                                                        style={{
                                                                            marginTop:
                                                                                "6px",

                                                                            opacity:
                                                                                "0.7",

                                                                            fontSize:
                                                                                "13px"
                                                                        }}
                                                                    >
                                                                        {
                                                                            scan.pages_scanned
                                                                        }
                                                                        {" "}
                                                                        pages
                                                                        {" • "}
                                                                        {
                                                                            scan.findings_created
                                                                        }
                                                                        {" "}
                                                                        categories
                                                                        {" • "}
                                                                        {
                                                                            scan.duration_ms
                                                                        }
                                                                        ms
                                                                    </div>

                                                                </div>


                                                                <div
                                                                    style={{
                                                                        display:
                                                                            "flex",

                                                                        alignItems:
                                                                            "center",

                                                                        gap:
                                                                            "12px"
                                                                    }}
                                                                >

                                                                    <span
                                                                        className="severity"
                                                                    >
                                                                        {
                                                                            scan.status
                                                                        }
                                                                    </span>

                                                                    <span>
                                                                        {
                                                                            scanOpen
                                                                                ? "−"
                                                                                : "+"
                                                                        }
                                                                    </span>

                                                                </div>

                                                            </div>


                                                            {/* =============================
                                                                FINDINGS
                                                            ============================= */}

                                                            {scanOpen && (

                                                                <div
                                                                    style={{
                                                                        padding:
                                                                            "0 18px 18px"
                                                                    }}
                                                                >

                                                                    {scan.findings.length ===
                                                                    0 ? (

                                                                        <div className="empty-state">
                                                                            No vulnerabilities
                                                                            detected
                                                                            in this
                                                                            scan.
                                                                        </div>

                                                                    ) : (

                                                                        scan.findings.map(
                                                                            (
                                                                                finding
                                                                            ) => {

                                                                                const findingOpen =
                                                                                    !!expandedFindings[
                                                                                        finding.id
                                                                                    ];


                                                                                return (
                                                                                    <div
                                                                                        key={
                                                                                            finding.id
                                                                                        }
                                                                                        style={{
                                                                                            borderTop:
                                                                                                "1px solid rgba(255,255,255,0.06)",

                                                                                            padding:
                                                                                                "16px 0"
                                                                                        }}
                                                                                    >

                                                                                        {/* =============================
                                                                                            FINDING CATEGORY
                                                                                        ============================= */}

                                                                                        <div
                                                                                            style={{
                                                                                                display:
                                                                                                    "flex",

                                                                                                justifyContent:
                                                                                                    "space-between",

                                                                                                alignItems:
                                                                                                    "center",

                                                                                                cursor:
                                                                                                    "pointer"
                                                                                            }}

                                                                                            onClick={() =>
                                                                                                toggleFinding(
                                                                                                    finding.id
                                                                                                )
                                                                                            }
                                                                                        >

                                                                                            <div>

                                                                                                <strong
                                                                                                    style={{
                                                                                                        fontSize:
                                                                                                            "16px"
                                                                                                    }}
                                                                                                >
                                                                                                    {
                                                                                                        finding.vulnerability
                                                                                                    }
                                                                                                </strong>

                                                                                                <div
                                                                                                    style={{
                                                                                                        marginTop:
                                                                                                            "6px",

                                                                                                        opacity:
                                                                                                            "0.7",

                                                                                                        fontSize:
                                                                                                            "13px"
                                                                                                    }}
                                                                                                >
                                                                                                    {
                                                                                                        finding.occurrences.length
                                                                                                    }
                                                                                                    {" "}
                                                                                                    affected
                                                                                                    location
                                                                                                    {
                                                                                                        finding.occurrences.length ===
                                                                                                        1
                                                                                                            ? ""
                                                                                                            : "s"
                                                                                                    }
                                                                                                </div>

                                                                                            </div>


                                                                                            <div
                                                                                                style={{
                                                                                                    display:
                                                                                                        "flex",

                                                                                                    alignItems:
                                                                                                        "center",

                                                                                                    gap:
                                                                                                        "12px"
                                                                                                }}
                                                                                            >

                                                                                                <span
                                                                                                    className={`severity ${
                                                                                                        finding.severity
                                                                                                            .toLowerCase()
                                                                                                    }`}
                                                                                                >
                                                                                                    {
                                                                                                        finding.severity
                                                                                                    }
                                                                                                </span>

                                                                                                <span>
                                                                                                    {
                                                                                                        findingOpen
                                                                                                            ? "−"
                                                                                                            : "+"
                                                                                                    }
                                                                                                </span>

                                                                                            </div>

                                                                                        </div>


                                                                                        {/* =============================
                                                                                            FINDING DETAILS
                                                                                        ============================= */}

                                                                                        {findingOpen && (

                                                                                            <div
                                                                                                style={{
                                                                                                    marginTop:
                                                                                                        "14px"
                                                                                                }}
                                                                                            >

                                                                                                <p>
                                                                                                    {
                                                                                                        finding.description
                                                                                                    }
                                                                                                </p>


                                                                                                {/* =========================
                                                                                                    AFFECTED LOCATIONS
                                                                                                ========================= */}

                                                                                                <div
                                                                                                    style={{
                                                                                                        marginTop:
                                                                                                            "16px"
                                                                                                    }}
                                                                                                >

                                                                                                    <strong>
                                                                                                        Affected
                                                                                                        locations
                                                                                                    </strong>


                                                                                                    <div
                                                                                                        style={{
                                                                                                            marginTop:
                                                                                                                "10px"
                                                                                                        }}
                                                                                                    >

                                                                                                        {finding.occurrences.map(
                                                                                                            (
                                                                                                                occurrence
                                                                                                            ) => (

                                                                                                                <div
                                                                                                                    key={
                                                                                                                        occurrence.id
                                                                                                                    }
                                                                                                                    style={{
                                                                                                                        padding:
                                                                                                                            "10px 12px",

                                                                                                                        marginBottom:
                                                                                                                            "6px",

                                                                                                                        borderRadius:
                                                                                                                            "6px",

                                                                                                                        background:
                                                                                                                            "rgba(255,255,255,0.03)"
                                                                                                                    }}
                                                                                                                >

                                                                                                                    <div>
                                                                                                                        {
                                                                                                                            occurrence.affected_module
                                                                                                                        }
                                                                                                                    </div>


                                                                                                                    {occurrence.detected_vulnerability !==
                                                                                                                        finding.vulnerability && (

                                                                                                                        <div
                                                                                                                            style={{
                                                                                                                                marginTop:
                                                                                                                                    "4px",

                                                                                                                                fontSize:
                                                                                                                                    "12px",

                                                                                                                                opacity:
                                                                                                                                    "0.65"
                                                                                                                            }}
                                                                                                                        >
                                                                                                                            Detected as:
                                                                                                                            {" "}
                                                                                                                            {
                                                                                                                                occurrence.detected_vulnerability
                                                                                                                            }
                                                                                                                        </div>

                                                                                                                    )}

                                                                                                                </div>

                                                                                                            )
                                                                                                        )}

                                                                                                    </div>

                                                                                                </div>


                                                                                                {/* =========================
                                                                                                    OBSERVED RESULT
                                                                                                ========================= */}

                                                                                                {finding.observed_result && (

                                                                                                    <div
                                                                                                        style={{
                                                                                                            marginTop:
                                                                                                                "16px"
                                                                                                        }}
                                                                                                    >

                                                                                                        <strong>
                                                                                                            Observed
                                                                                                            result
                                                                                                        </strong>

                                                                                                        <p
                                                                                                            style={{
                                                                                                                whiteSpace:
                                                                                                                    "pre-line"
                                                                                                            }}
                                                                                                        >
                                                                                                            {
                                                                                                                finding.observed_result
                                                                                                            }
                                                                                                        </p>

                                                                                                    </div>

                                                                                                )}


                                                                                                {/* =========================
                                                                                                    IMPACT
                                                                                                ========================= */}

                                                                                                {finding.impact && (

                                                                                                    <div
                                                                                                        style={{
                                                                                                            marginTop:
                                                                                                                "16px"
                                                                                                        }}
                                                                                                    >

                                                                                                        <strong>
                                                                                                            Impact
                                                                                                        </strong>

                                                                                                        <p
                                                                                                            style={{
                                                                                                                whiteSpace:
                                                                                                                    "pre-line"
                                                                                                            }}
                                                                                                        >
                                                                                                            {
                                                                                                                finding.impact
                                                                                                            }
                                                                                                        </p>

                                                                                                    </div>

                                                                                                )}

                                                                                            </div>

                                                                                        )}

                                                                                    </div>
                                                                                );
                                                                            }
                                                                        )

                                                                    )}

                                                                </div>

                                                            )}

                                                        </div>
                                                    );
                                                }
                                            )

                                        )}

                                    </div>

                                )}

                            </div>
                        );
                    }
                )}

        </div>
    );
}


export default Findings;