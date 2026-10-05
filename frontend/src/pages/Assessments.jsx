import {
    useEffect,
    useState
} from "react";

import {
    Plus,
    ShieldCheck,
    X,
    Play,
    Loader2
} from "lucide-react";

import api from "../services/api";


function Assessments() {

    const [
        assessments,
        setAssessments
    ] = useState([]);


    const [
        showForm,
        setShowForm
    ] = useState(false);


    const [
        form,
        setForm
    ] = useState({

        title: "",

        target_url:
            "http://localhost/DVWA",

        scope_description: "",

        tester: ""
    });


    const [
        loading,
        setLoading
    ] = useState(true);


    const [
        scanningId,
        setScanningId
    ] = useState(null);


    const [
        scanResult,
        setScanResult
    ] = useState(null);


    // =====================================================
    // LOAD ASSESSMENTS
    // =====================================================

    const loadAssessments =
        async () => {

            try {

                const response =
                    await api.get(
                        "/assessments"
                    );

                setAssessments(
                    response.data
                );

            } catch (error) {

                console.error(
                    error
                );

            } finally {

                setLoading(
                    false
                );
            }
        };


    useEffect(() => {

        loadAssessments();

    }, []);


    // =====================================================
    // FORM CHANGE
    // =====================================================

    const handleChange =
        (event) => {

            setForm({
                ...form,

                [event.target.name]:
                    event.target.value
            });
        };


    // =====================================================
    // CREATE ASSESSMENT
    // =====================================================

    const createAssessment =
        async (event) => {

            event.preventDefault();


            try {

                await api.post(
                    "/assessments",
                    form
                );


                setForm({

                    title: "",

                    target_url:
                        "http://localhost/DVWA",

                    scope_description: "",

                    tester: ""
                });


                setShowForm(
                    false
                );


                await loadAssessments();


            } catch (error) {

                console.error(
                    error
                );


                alert(
                    error.response
                        ?.data
                        ?.error ||
                    "Failed to create assessment"
                );
            }
        };


    // =====================================================
    // RUN AUTOMATED SCAN
    // =====================================================

    const runScan =
        async (assessment) => {

            const confirmed =
                window.confirm(
                    `Run the automated security scan against ${assessment.target_url}?`
                );


            if (!confirmed) {
                return;
            }


            setScanningId(
                assessment.id
            );


            setScanResult(
                null
            );


            try {

                const response =
                    await api.post(
                        `/scans/${assessment.id}`
                    );


                setScanResult(
                    response.data
                );


                await loadAssessments();


            } catch (error) {

                console.error(
                    "Scan error:",
                    error
                );


                alert(
                    error.response
                        ?.data
                        ?.error ||
                    "Scan failed"
                );


            } finally {

                setScanningId(
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
                        ASSESSMENTS
                    </p>

                    <h2>
                        Security Assessments
                    </h2>

                    <p>
                        Manage authorized
                        testing engagements.
                    </p>

                </div>


                <button
                    className="primary-btn"

                    onClick={() =>
                        setShowForm(
                            true
                        )
                    }
                >

                    <Plus
                        size={18}
                    />

                    New Assessment

                </button>

            </div>


            {/* =================================================
                CREATE ASSESSMENT
            ================================================= */}

            {showForm && (

                <div className="panel">

                    <div className="panel-header">

                        <div>

                            <h3>
                                Create Assessment
                            </h3>

                            <p>
                                Register a new
                                authorized test.
                            </p>

                        </div>


                        <button
                            className="primary-btn"

                            type="button"

                            onClick={() =>
                                setShowForm(
                                    false
                                )
                            }
                        >

                            <X
                                size={16}
                            />

                            Close

                        </button>

                    </div>


                    <form
                        onSubmit={
                            createAssessment
                        }

                        className="form-grid"
                    >

                        <input
                            name="title"

                            placeholder=
                                "Assessment title"

                            value={
                                form.title
                            }

                            onChange={
                                handleChange
                            }

                            required
                        />


                        <input
                            name="target_url"

                            placeholder=
                                "Target URL"

                            value={
                                form.target_url
                            }

                            onChange={
                                handleChange
                            }

                            required
                        />


                        <input
                            name="tester"

                            placeholder=
                                "Tester name"

                            value={
                                form.tester
                            }

                            onChange={
                                handleChange
                            }
                        />


                        <textarea
                            name="scope_description"

                            placeholder=
                                "Scope description"

                            value={
                                form.scope_description
                            }

                            onChange={
                                handleChange
                            }

                            rows="4"
                        />


                        <button
                            className="primary-btn"

                            type="submit"
                        >

                            Create Assessment

                        </button>

                    </form>

                </div>
            )}


            {/* =================================================
                SCAN RESULT
            ================================================= */}

            {scanResult && (

                <div className="panel">

                    <div className="panel-header">

                        <div>

                            <p className="eyebrow">
                                SCAN RESULTS
                            </p>

                            <h3>
                                Scan #{scanResult.scan_number} Completed
                            </h3>

                            <p>
                                The automated scanner
                                completed successfully.
                            </p>

                        </div>


                        <button
                            className="primary-btn"

                            type="button"

                            onClick={() =>
                                setScanResult(
                                    null
                                )
                            }
                        >

                            Close

                        </button>

                    </div>


                    {/* =================================================
                        SCAN SUMMARY
                    ================================================= */}

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns:
                                "repeat(auto-fit, minmax(180px, 1fr))",
                            gap: "12px",
                            marginBottom: "20px"
                        }}
                    >

                        <div
                            className="panel"
                            style={{
                                margin: 0,
                                padding: "16px"
                            }}
                        >

                            <strong>
                                Pages Scanned
                            </strong>

                            <div
                                style={{
                                    fontSize: "24px",
                                    fontWeight: "700",
                                    marginTop: "6px"
                                }}
                            >
                                {
                                    scanResult.pages_scanned ??
                                    0
                                }
                            </div>

                        </div>


                        <div
                            className="panel"
                            style={{
                                margin: 0,
                                padding: "16px"
                            }}
                        >

                            <strong>
                                Vulnerabilities Detected
                            </strong>

                            <div
                                style={{
                                    fontSize: "24px",
                                    fontWeight: "700",
                                    marginTop: "6px"
                                }}
                            >
                                {
                                    scanResult.findings_detected ??
                                    0
                                }
                            </div>

                            <small>
                                Individual detected
                                occurrences
                            </small>

                        </div>


                        <div
                            className="panel"
                            style={{
                                margin: 0,
                                padding: "16px"
                            }}
                        >

                            <strong>
                                Findings Created
                            </strong>

                            <div
                                style={{
                                    fontSize: "24px",
                                    fontWeight: "700",
                                    marginTop: "6px"
                                }}
                            >
                                {
                                    scanResult.findings_created ??
                                    0
                                }
                            </div>

                            <small>
                                Vulnerability categories
                            </small>

                        </div>


                        <div
                            className="panel"
                            style={{
                                margin: 0,
                                padding: "16px"
                            }}
                        >

                            <strong>
                                Duration
                            </strong>

                            <div
                                style={{
                                    fontSize: "24px",
                                    fontWeight: "700",
                                    marginTop: "6px"
                                }}
                            >
                                {
                                    scanResult.duration_ms
                                        ? `${(
                                            scanResult.duration_ms /
                                            1000
                                        ).toFixed(2)}s`
                                        : "0s"
                                }
                            </div>

                        </div>

                    </div>


                    {/* =================================================
                        FINDINGS
                    ================================================= */}

                    {scanResult.findings &&
                    scanResult.findings.length >
                        0 ? (

                        <div className="table-container">

                            <table className="data-table">

                                <thead>

                                    <tr>

                                        <th>
                                            Vulnerability
                                        </th>

                                        <th>
                                            Affected Locations
                                        </th>

                                        <th>
                                            Occurrences
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

                                    {
                                        scanResult.findings.map(
                                            (
                                                finding
                                            ) => (

                                                <tr
                                                    key={
                                                        finding.id
                                                    }
                                                >

                                                    <td>

                                                        <strong>
                                                            {
                                                                finding.vulnerability
                                                            }
                                                        </strong>

                                                    </td>


                                                    <td>

                                                        {
                                                            finding.affected_module
                                                        }

                                                    </td>


                                                    <td>

                                                        {
                                                            finding.occurrence_count ??
                                                            0
                                                        }

                                                    </td>


                                                    <td>

                                                        <span
                                                            className={
                                                                `severity ${String(
                                                                    finding.severity
                                                                ).toLowerCase()}`
                                                            }
                                                        >

                                                            {
                                                                finding.severity
                                                            }

                                                        </span>

                                                    </td>


                                                    <td>

                                                        {
                                                            finding.status
                                                        }

                                                    </td>

                                                </tr>

                                            )
                                        )
                                    }

                                </tbody>

                            </table>

                        </div>

                    ) : (

                        <div className="empty-state">

                            No vulnerabilities
                            were detected by
                            the current scanner
                            checks.

                        </div>

                    )}

                </div>
            )}


            {/* =================================================
                ASSESSMENT LIST
            ================================================= */}

            {loading ? (

                <div className="panel">

                    Loading assessments...

                </div>

            ) : (

                <div className="assessment-grid">

                    {
                        assessments.map(
                            (
                                assessment
                            ) => (

                                <div
                                    className="assessment-card"

                                    key={
                                        assessment.id
                                    }
                                >

                                    <div className="assessment-icon">

                                        <ShieldCheck
                                            size={24}
                                        />

                                    </div>


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


                                    <span className="badge blue">

                                        {
                                            assessment.status
                                        }

                                    </span>


                                    {/* ============================
                                        RUN SCAN BUTTON
                                    ============================ */}

                                    <button

                                        className="primary-btn"

                                        type="button"

                                        disabled={
                                            scanningId ===
                                            assessment.id
                                        }

                                        onClick={() =>
                                            runScan(
                                                assessment
                                            )
                                        }

                                        style={{
                                            marginTop:
                                                "14px"
                                        }}
                                    >

                                        {
                                            scanningId ===
                                            assessment.id
                                                ? (
                                                    <>
                                                        <Loader2
                                                            size={16}
                                                            className="scan-spinner"
                                                        />

                                                        Scanning...
                                                    </>
                                                )
                                                : (
                                                    <>
                                                        <Play
                                                            size={16}
                                                        />

                                                        Run Scan
                                                    </>
                                                )
                                        }

                                    </button>

                                </div>

                            )
                        )
                    }


                    {
                        assessments.length ===
                        0 && (

                            <div className="panel">

                                No assessments
                                created yet.

                            </div>

                        )
                    }

                </div>

            )}

        </div>
    );
}


export default Assessments;