import { useEffect, useState } from "react";

import {
    Save,
    Trash2,
    Eye,
    FileCode2,
    RefreshCw,
    X
} from "lucide-react";

import api from "./services/api";

function HttpRequests() {

    const emptyForm = {
        assessment_id: "",
        rawRequest: "",
        method: "POST",
        url: "",
        host: "",
        headers: "",
        body: ""
    };

    const [requests, setRequests] = useState([]);
    const [assessments, setAssessments] = useState([]);

    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);

    const [message, setMessage] = useState("");
    const [error, setError] = useState("");

    const [selectedRequest, setSelectedRequest] = useState(null);

    const [form, setForm] = useState(emptyForm);


    /* =====================================================
       LOAD REQUESTS + ASSESSMENTS
       ===================================================== */

    const loadData = async () => {

        setLoading(true);
        setError("");

        try {

            const [
                requestsResponse,
                assessmentsResponse
            ] = await Promise.all([
                api.get("/requests"),
                api.get("/assessments")
            ]);

            setRequests(
                Array.isArray(requestsResponse.data)
                    ? requestsResponse.data
                    : []
            );

            setAssessments(
                Array.isArray(assessmentsResponse.data)
                    ? assessmentsResponse.data
                    : []
            );

        } catch (err) {

            console.error("Load HTTP request data error:", err);

            setError(
                err.response?.data?.error ||
                "Failed to load HTTP request data."
            );

        } finally {

            setLoading(false);

        }
    };


    useEffect(() => {

        loadData();

    }, []);


    /* =====================================================
       PARSE RAW BURP REQUEST
       ===================================================== */

    const parseRequest = (value) => {

        const normalized = value
            .replace(/\r\n/g, "\n")
            .replace(/\r/g, "\n");


        if (!normalized.trim()) {

            setForm((previous) => ({
                ...previous,

                method: "POST",
                url: "",
                host: "",
                headers: "",
                body: ""
            }));

            return;
        }


        const lines = normalized.split("\n");

        const requestLine =
            lines[0]?.trim() || "";


        const parts =
            requestLine.split(/\s+/);


        let method = "POST";
        let url = "";


        if (parts.length >= 2) {

            method =
                parts[0].toUpperCase();

            url =
                parts[1];

        }


        /* -----------------------------------------------
           Separate headers and body
           ----------------------------------------------- */

        const separator =
            normalized.indexOf("\n\n");

        let headerSection =
            normalized;

        let bodySection = "";


        if (separator !== -1) {

            headerSection =
                normalized.substring(
                    0,
                    separator
                );

            bodySection =
                normalized.substring(
                    separator + 2
                );

        }


        /* -----------------------------------------------
           Extract headers
           ----------------------------------------------- */

        const headerLines =
            headerSection.split("\n");


        const headerText =
            headerLines
                .slice(1)
                .join("\n");


        /* -----------------------------------------------
           Extract Host
           ----------------------------------------------- */

        const hostLine =
            headerLines.find(
                (line) =>
                    line
                        .toLowerCase()
                        .startsWith("host:")
            );


        const host =
            hostLine
                ? hostLine
                    .substring(5)
                    .trim()
                : "";


        setForm((previous) => ({
            ...previous,

            method,
            url,
            host,
            headers: headerText,
            body: bodySection
        }));

    };


    /* =====================================================
       RAW REQUEST CHANGE
       ===================================================== */

    const handleRawRequestChange = (event) => {

        const value =
            event.target.value;

        setForm((previous) => ({
            ...previous,
            rawRequest: value
        }));

        parseRequest(value);

        setMessage("");
        setError("");

    };


    /* =====================================================
       ASSESSMENT CHANGE
       ===================================================== */

    const handleAssessmentChange = (event) => {

        setForm((previous) => ({
            ...previous,
            assessment_id:
                event.target.value
        }));

        setMessage("");
        setError("");

    };


    /* =====================================================
       SAVE REQUEST
       ===================================================== */

    const saveRequest = async (event) => {

        event.preventDefault();

        setMessage("");
        setError("");


        if (!form.rawRequest.trim()) {

            setError(
                "Paste a raw Burp HTTP request first."
            );

            return;
        }


        setSaving(true);


        try {

            await api.post(
                "/requests",
                {
                    assessment_id:
                        form.assessment_id
                            ? Number(form.assessment_id)
                            : null,

                    method:
                        form.method,

                    url:
                        form.url,

                    host:
                        form.host,

                    headers:
                        form.headers,

                    body:
                        form.body,

                    raw_request:
                        form.rawRequest
                }
            );


            setMessage(
                "HTTP request saved successfully."
            );


            setForm({
                ...emptyForm,

                assessment_id:
                    form.assessment_id
            });


            await loadData();

        } catch (err) {

            console.error(
                "Save HTTP request error:",
                err
            );

            setError(
                err.response?.data?.error ||
                "Failed to save HTTP request."
            );

        } finally {

            setSaving(false);

        }

    };


    /* =====================================================
       DELETE REQUEST
       ===================================================== */

    const deleteRequest = async (id) => {

        const confirmed =
            window.confirm(
                "Delete this saved HTTP request?"
            );


        if (!confirmed) {
            return;
        }


        try {

            await api.delete(
                `/requests/${id}`
            );


            setMessage(
                "HTTP request deleted."
            );


            if (
                selectedRequest?.id === id
            ) {

                setSelectedRequest(null);

            }


            await loadData();

        } catch (err) {

            console.error(
                "Delete HTTP request error:",
                err
            );

            setError(
                err.response?.data?.error ||
                "Failed to delete HTTP request."
            );

        }

    };


    /* =====================================================
       CLEAR FORM
       ===================================================== */

    const clearForm = () => {

        setForm({
            ...emptyForm,
            assessment_id:
                form.assessment_id
        });

        setMessage("");
        setError("");

    };


    /* =====================================================
       VIEW REQUEST
       ===================================================== */

    const viewRequest = (request) => {

        setSelectedRequest(request);

        setMessage("");
        setError("");

    };


    /* =====================================================
       RENDER
       ===================================================== */

    return (

        <div>

            {/* =================================================
                HEADER
               ================================================= */}

            <div className="page-header">

                <div>

                    <p className="eyebrow">
                        HTTP ANALYSIS
                    </p>

                    <h2>
                        HTTP Requests
                    </h2>

                    <p>
                        Store and analyze HTTP
                        requests captured during
                        controlled security testing.
                    </p>

                </div>

            </div>


            {/* =================================================
                GLOBAL MESSAGE
               ================================================= */}

            {message && (

                <div
                    style={{
                        marginBottom: "18px",
                        padding: "11px 14px",
                        borderRadius: "8px",
                        background:
                            "rgba(34, 197, 94, 0.08)",
                        border:
                            "1px solid rgba(34, 197, 94, 0.20)",
                        color: "#4ade80",
                        fontSize: "11px"
                    }}
                >
                    {message}
                </div>

            )}


            {error && (

                <div
                    style={{
                        marginBottom: "18px",
                        padding: "11px 14px",
                        borderRadius: "8px",
                        background:
                            "rgba(239, 68, 68, 0.08)",
                        border:
                            "1px solid rgba(239, 68, 68, 0.20)",
                        color: "#f87171",
                        fontSize: "11px"
                    }}
                >
                    {error}
                </div>

            )}


            {/* =================================================
                CAPTURE REQUEST
               ================================================= */}

            <div className="panel">

                <div className="panel-header">

                    <div>

                        <h3>
                            Capture HTTP Request
                        </h3>

                        <p>
                            Copy a request from Burp Suite
                            HTTP history and paste it below.
                        </p>

                    </div>

                    <FileCode2
                        size={24}
                        color="#42a7ff"
                    />

                </div>


                <form onSubmit={saveRequest}>


                    {/* -----------------------------------------
                        ASSESSMENT
                       ----------------------------------------- */}

                    <div
                        style={{
                            marginBottom: "15px"
                        }}
                    >

                        <label
                            style={{
                                display: "block",
                                marginBottom: "7px",
                                fontSize: "11px",
                                color: "#9eb6ce",
                                fontWeight: "600"
                            }}
                        >
                            Assessment
                        </label>


                        <select
                            value={form.assessment_id}
                            onChange={
                                handleAssessmentChange
                            }
                            style={{
                                width: "100%",
                                maxWidth: "500px",
                                padding: "11px 12px"
                            }}
                        >

                            <option value="">
                                No assessment selected
                            </option>


                            {assessments.map(
                                (assessment) => (

                                    <option
                                        key={
                                            assessment.id
                                        }
                                        value={
                                            assessment.id
                                        }
                                    >
                                        {assessment.title}
                                    </option>

                                )
                            )}

                        </select>

                    </div>


                    {/* -----------------------------------------
                        RAW REQUEST
                       ----------------------------------------- */}

                    <div>

                        <label
                            style={{
                                display: "block",
                                marginBottom: "7px",
                                fontSize: "11px",
                                color: "#9eb6ce",
                                fontWeight: "600"
                            }}
                        >
                            Raw Burp HTTP Request
                        </label>


                        <textarea
                            value={form.rawRequest}
                            onChange={
                                handleRawRequestChange
                            }
                            placeholder={`POST /DVWA/vulnerabilities/sqli/ HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=...

id=1&Submit=Submit`}
                            rows={18}
                            className="http-request-editor"
                        />

                    </div>


                    {/* =================================================
                        PARSED REQUEST
                       ================================================= */}

                    <div
                        className="panel"
                        style={{
                            marginTop: "20px",
                            marginBottom: "0",
                            background:
                                "rgba(7, 21, 37, 0.65)"
                        }}
                    >

                        <div className="panel-header">

                            <div>

                                <h3>
                                    Parsed Request
                                </h3>

                                <p>
                                    Automatically extracted
                                    from the raw Burp request.
                                </p>

                            </div>

                        </div>


                        <div className="form-grid">

                            <div>

                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "10px",
                                        color: "#6687a7"
                                    }}
                                >
                                    Method
                                </label>

                                <input
                                    value={form.method}
                                    readOnly
                                    placeholder="Method"
                                />

                            </div>


                            <div>

                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "10px",
                                        color: "#6687a7"
                                    }}
                                >
                                    Host
                                </label>

                                <input
                                    value={form.host}
                                    readOnly
                                    placeholder="Host"
                                />

                            </div>


                            <div
                                style={{
                                    gridColumn:
                                        "1 / -1"
                                }}
                            >

                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "10px",
                                        color: "#6687a7"
                                    }}
                                >
                                    URL / Path
                                </label>

                                <input
                                    value={form.url}
                                    readOnly
                                    placeholder="URL"
                                />

                            </div>


                            <div
                                style={{
                                    gridColumn:
                                        "1 / -1"
                                }}
                            >

                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "10px",
                                        color: "#6687a7"
                                    }}
                                >
                                    Headers
                                </label>

                                <textarea
                                    value={form.headers}
                                    readOnly
                                    rows={6}
                                    placeholder="Headers"
                                />

                            </div>


                            <div
                                style={{
                                    gridColumn:
                                        "1 / -1"
                                }}
                            >

                                <label
                                    style={{
                                        display: "block",
                                        marginBottom: "6px",
                                        fontSize: "10px",
                                        color: "#6687a7"
                                    }}
                                >
                                    Body
                                </label>

                                <textarea
                                    value={form.body}
                                    readOnly
                                    rows={6}
                                    placeholder="Body"
                                />

                            </div>

                        </div>

                    </div>


                    {/* -----------------------------------------
                        FORM ACTIONS
                       ----------------------------------------- */}

                    <div
                        style={{
                            display: "flex",
                            gap: "9px",
                            marginTop: "16px",
                            flexWrap: "wrap"
                        }}
                    >

                        <button
                            className="primary-btn"
                            type="submit"
                            disabled={saving}
                        >

                            <Save size={17} />

                            {saving
                                ? "Saving..."
                                : "Save HTTP Request"}

                        </button>


                        <button
                            type="button"
                            className="secondary-btn"
                            onClick={clearForm}
                            disabled={saving}
                        >

                            <RefreshCw size={15} />

                            Clear

                        </button>

                    </div>

                </form>

            </div>


            {/* =================================================
                SAVED REQUESTS
               ================================================= */}

            <div
                className="panel"
                style={{
                    marginTop: "20px"
                }}
            >

                <div className="panel-header">

                    <div>

                        <h3>
                            Saved HTTP Requests
                        </h3>

                        <p>
                            Requests captured from
                            controlled testing.
                        </p>

                    </div>

                    <span className="badge blue">
                        {requests.length} REQUESTS
                    </span>

                </div>


                {loading ? (

                    <div className="empty-large">

                        <RefreshCw
                            size={25}
                            style={{
                                animation:
                                    "spin 1s linear infinite"
                            }}
                        />

                        <h3>
                            Loading HTTP requests...
                        </h3>

                    </div>

                ) : requests.length === 0 ? (

                    <div className="empty-large">

                        <FileCode2 size={30} />

                        <h3>
                            No HTTP requests saved yet.
                        </h3>

                        <p>
                            Capture a request from Burp Suite
                            and save it above.
                        </p>

                    </div>

                ) : (

                    <div className="table-container">

                        <table className="data-table">

                            <thead>

                                <tr>

                                    <th>
                                        ID
                                    </th>

                                    <th>
                                        Assessment
                                    </th>

                                    <th>
                                        Method
                                    </th>

                                    <th>
                                        Host
                                    </th>

                                    <th>
                                        URL
                                    </th>

                                    <th>
                                        Date
                                    </th>

                                    <th>
                                        Actions
                                    </th>

                                </tr>

                            </thead>


                            <tbody>

                                {requests.map(
                                    (request) => (

                                        <tr
                                            key={
                                                request.id
                                            }
                                        >

                                            <td>
                                                #
                                                {request.id}
                                            </td>


                                            <td>

                                                {request.assessment_title ||
                                                    "Unassigned"}

                                            </td>


                                            <td>

                                                <span
                                                    className="http-method"
                                                >
                                                    {request.method}
                                                </span>

                                            </td>


                                            <td>

                                                {request.host ||
                                                    "-"}

                                            </td>


                                            <td>

                                                <div
                                                    className="request-url"
                                                    title={
                                                        request.url ||
                                                        "-"
                                                    }
                                                >
                                                    {
                                                        request.url ||
                                                        "-"
                                                    }
                                                </div>

                                            </td>


                                            <td>

                                                {request.created_at
                                                    ? new Date(
                                                        request.created_at
                                                    ).toLocaleString()
                                                    : "-"}

                                            </td>


                                            <td>

                                                <button
                                                    type="button"
                                                    className="secondary-btn"
                                                    onClick={() =>
                                                        viewRequest(
                                                            request
                                                        )
                                                    }
                                                >

                                                    <Eye
                                                        size={14}
                                                    />

                                                    View

                                                </button>


                                                <button
                                                    type="button"
                                                    className="danger-btn"
                                                    onClick={() =>
                                                        deleteRequest(
                                                            request.id
                                                        )
                                                    }
                                                >

                                                    <Trash2
                                                        size={14}
                                                    />

                                                    Delete

                                                </button>

                                            </td>

                                        </tr>

                                    )
                                )}

                            </tbody>

                        </table>

                    </div>

                )}

            </div>


            {/* =================================================
                REQUEST DETAILS
               ================================================= */}

            {selectedRequest && (

                <div
                    className="panel"
                    style={{
                        marginTop: "20px"
                    }}
                >

                    <div className="panel-header">

                        <div>

                            <h3>
                                Request #
                                {selectedRequest.id}
                            </h3>

                            <p>
                                Raw HTTP request
                            </p>

                        </div>


                        <button
                            type="button"
                            className="secondary-btn"
                            onClick={() =>
                                setSelectedRequest(null)
                            }
                        >

                            <X size={14} />

                            Close

                        </button>

                    </div>


                    {/* Request metadata */}

                    <div
                        style={{
                            display: "grid",
                            gridTemplateColumns:
                                "repeat(4, minmax(0, 1fr))",
                            gap: "10px",
                            marginBottom: "15px"
                        }}
                    >

                        <div
                            style={{
                                padding: "11px",
                                border:
                                    "1px solid var(--border)",
                                borderRadius: "8px",
                                background: "#081a2d"
                            }}
                        >

                            <small
                                style={{
                                    display: "block",
                                    color: "#6687a7",
                                    fontSize: "9px",
                                    marginBottom: "5px"
                                }}
                            >
                                METHOD
                            </small>

                            <strong
                                style={{
                                    color: "#70bdff",
                                    fontSize: "11px"
                                }}
                            >
                                {selectedRequest.method}
                            </strong>

                        </div>


                        <div
                            style={{
                                padding: "11px",
                                border:
                                    "1px solid var(--border)",
                                borderRadius: "8px",
                                background: "#081a2d"
                            }}
                        >

                            <small
                                style={{
                                    display: "block",
                                    color: "#6687a7",
                                    fontSize: "9px",
                                    marginBottom: "5px"
                                }}
                            >
                                HOST
                            </small>

                            <strong
                                style={{
                                    color: "#dbeafe",
                                    fontSize: "11px"
                                }}
                            >
                                {selectedRequest.host ||
                                    "-"}
                            </strong>

                        </div>


                        <div
                            style={{
                                padding: "11px",
                                border:
                                    "1px solid var(--border)",
                                borderRadius: "8px",
                                background: "#081a2d"
                            }}
                        >

                            <small
                                style={{
                                    display: "block",
                                    color: "#6687a7",
                                    fontSize: "9px",
                                    marginBottom: "5px"
                                }}
                            >
                                ASSESSMENT
                            </small>

                            <strong
                                style={{
                                    color: "#dbeafe",
                                    fontSize: "11px"
                                }}
                            >
                                {selectedRequest.assessment_title ||
                                    "Unassigned"}
                            </strong>

                        </div>


                        <div
                            style={{
                                padding: "11px",
                                border:
                                    "1px solid var(--border)",
                                borderRadius: "8px",
                                background: "#081a2d"
                            }}
                        >

                            <small
                                style={{
                                    display: "block",
                                    color: "#6687a7",
                                    fontSize: "9px",
                                    marginBottom: "5px"
                                }}
                            >
                                CREATED
                            </small>

                            <strong
                                style={{
                                    color: "#dbeafe",
                                    fontSize: "10px"
                                }}
                            >
                                {selectedRequest.created_at
                                    ? new Date(
                                        selectedRequest.created_at
                                    ).toLocaleString()
                                    : "-"}
                            </strong>

                        </div>

                    </div>


                    {/* Raw request */}

                    <pre className="raw-request-viewer">
                        {selectedRequest.raw_request ||
                            "No raw request available."}
                    </pre>

                </div>

            )}

        </div>

    );
}

export default HttpRequests;