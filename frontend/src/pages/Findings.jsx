import {
    useEffect,
    useState
} from "react";

import api from "../services/api";

function Findings() {
    const [findings, setFindings] =
        useState([]);

    const [assessments, setAssessments] =
        useState([]);

    const [search, setSearch] =
        useState("");

    const [showForm, setShowForm] =
        useState(false);

    const [editingId, setEditingId] =
        useState(null);

    const emptyForm = {
        assessment_id: "",
        vulnerability: "",
        affected_module: "",
        description: "",
        observed_result: "",
        impact: "",
        severity: "High",
        mitigation: "",
        status: "Open"
    };

    const [form, setForm] =
        useState(emptyForm);

    const loadData = async () => {
        try {
            const [
                findingsResponse,
                assessmentsResponse
            ] = await Promise.all([
                api.get("/findings"),
                api.get("/assessments")
            ]);

            setFindings(
                findingsResponse.data
            );

            setAssessments(
                assessmentsResponse.data
            );
        } catch (error) {
            console.error(error);
        }
    };

    useEffect(() => {
        loadData();
    }, []);

    const handleChange = (event) => {
        setForm({
            ...form,
            [event.target.name]:
                event.target.value
        });
    };

    const openCreate = () => {
        setEditingId(null);
        setForm({
            ...emptyForm,
            assessment_id:
                assessments[0]?.id || ""
        });
        setShowForm(true);
    };

    const openEdit = (finding) => {
        setEditingId(finding.id);

        setForm({
            assessment_id:
                finding.assessment_id,
            vulnerability:
                finding.vulnerability || "",
            affected_module:
                finding.affected_module || "",
            description:
                finding.description || "",
            observed_result:
                finding.observed_result || "",
            impact:
                finding.impact || "",
            severity:
                finding.severity || "High",
            mitigation:
                finding.mitigation || "",
            status:
                finding.status || "Open"
        });

        setShowForm(true);
    };

    const saveFinding =
        async (event) => {
            event.preventDefault();

            try {
                if (editingId) {
                    await api.put(
                        `/findings/${editingId}`,
                        form
                    );
                } else {
                    await api.post(
                        "/findings",
                        form
                    );
                }

                setForm(emptyForm);
                setEditingId(null);
                setShowForm(false);

                await loadData();
            } catch (error) {
                console.error(error);

                alert(
                    error.response?.data?.error ||
                    "Failed to save finding"
                );
            }
        };

    const deleteFinding =
        async (id) => {
            if (
                !window.confirm(
                    "Delete this finding?"
                )
            ) {
                return;
            }

            try {
                await api.delete(
                    `/findings/${id}`
                );

                await loadData();
            } catch (error) {
                console.error(error);

                alert(
                    "Failed to delete finding"
                );
            }
        };

    const filteredFindings =
        findings.filter((finding) =>
            `${finding.vulnerability}
             ${finding.severity}
             ${finding.status}
             ${finding.affected_module || ""}`
                .toLowerCase()
                .includes(
                    search.toLowerCase()
                )
        );

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        VULNERABILITY MANAGEMENT
                    </p>

                    <h2>
                        Security Findings
                    </h2>

                    <p>
                        Record and track
                        identified
                        vulnerabilities.
                    </p>
                </div>

                <button
                    className="primary-btn"
                    onClick={openCreate}
                    disabled={
                        assessments.length === 0
                    }
                >
                    Add Finding
                </button>
            </div>

            {assessments.length === 0 && (
                <div className="panel">
                    Create an assessment
                    before adding a
                    finding.
                </div>
            )}

            {showForm && (
                <div className="panel">
                    <div className="panel-header">
                        <h3>
                            {editingId
                                ? "Edit Finding"
                                : "Add Finding"}
                        </h3>

                        <button
                            className="primary-btn"
                            type="button"
                            onClick={() =>
                                setShowForm(false)
                            }
                        >
                            Close
                        </button>
                    </div>

                    <form
                        onSubmit={saveFinding}
                        className="form-grid"
                    >
                        <select
                            name="assessment_id"
                            value={
                                form.assessment_id
                            }
                            onChange={
                                handleChange
                            }
                            required
                        >
                            <option value="">
                                Select assessment
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
                                        {
                                            assessment.title
                                        }
                                    </option>
                                )
                            )}
                        </select>

                        <input
                            name="vulnerability"
                            placeholder="Vulnerability"
                            value={
                                form.vulnerability
                            }
                            onChange={
                                handleChange
                            }
                            required
                        />

                        <input
                            name="affected_module"
                            placeholder="Affected module"
                            value={
                                form.affected_module
                            }
                            onChange={
                                handleChange
                            }
                        />

                        <select
                            name="severity"
                            value={
                                form.severity
                            }
                            onChange={
                                handleChange
                            }
                        >
                            <option>
                                Critical
                            </option>
                            <option>
                                High
                            </option>
                            <option>
                                Medium
                            </option>
                            <option>
                                Low
                            </option>
                            <option>
                                Info
                            </option>
                        </select>

                        <select
                            name="status"
                            value={
                                form.status
                            }
                            onChange={
                                handleChange
                            }
                        >
                            <option>
                                Open
                            </option>
                            <option>
                                In Progress
                            </option>
                            <option>
                                Resolved
                            </option>
                        </select>

                        <textarea
                            name="description"
                            placeholder="Description"
                            value={
                                form.description
                            }
                            onChange={
                                handleChange
                            }
                            rows="3"
                        />

                        <textarea
                            name="observed_result"
                            placeholder="Observed result"
                            value={
                                form.observed_result
                            }
                            onChange={
                                handleChange
                            }
                            rows="3"
                        />

                        <textarea
                            name="impact"
                            placeholder="Impact"
                            value={
                                form.impact
                            }
                            onChange={
                                handleChange
                            }
                            rows="3"
                        />

                        <textarea
                            name="mitigation"
                            placeholder="Recommended mitigation"
                            value={
                                form.mitigation
                            }
                            onChange={
                                handleChange
                            }
                            rows="3"
                        />

                        <button
                            className="primary-btn"
                            type="submit"
                        >
                            Save Finding
                        </button>
                    </form>
                </div>
            )}

            <div className="panel">
                <div className="table-header">
                    <h3>
                        All Findings
                    </h3>

                    <input
                        type="text"
                        placeholder="Search findings..."
                        value={search}
                        onChange={(event) =>
                            setSearch(
                                event.target.value
                            )
                        }
                        className="search-input"
                    />
                </div>

                {filteredFindings.length ===
                0 ? (
                    <div className="empty-state">
                        No findings found.
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
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
                                    <th>
                                        Actions
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {filteredFindings.map(
                                    (finding) => (
                                        <tr
                                            key={
                                                finding.id
                                            }
                                        >
                                            <td>
                                                #
                                                {
                                                    finding.id
                                                }
                                            </td>

                                            <td>
                                                <strong>
                                                    {
                                                        finding.vulnerability
                                                    }
                                                </strong>
                                            </td>

                                            <td>
                                                {
                                                    finding.affected_module ||
                                                    "-"
                                                }
                                            </td>

                                            <td>
                                                {
                                                    finding.severity
                                                }
                                            </td>

                                            <td>
                                                {
                                                    finding.status
                                                }
                                            </td>

                                            <td>
                                                <button
                                                    onClick={() =>
                                                        openEdit(
                                                            finding
                                                        )
                                                    }
                                                >
                                                    Edit
                                                </button>

                                                <button
                                                    onClick={() =>
                                                        deleteFinding(
                                                            finding.id
                                                        )
                                                    }
                                                >
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
        </div>
    );
}

export default Findings;