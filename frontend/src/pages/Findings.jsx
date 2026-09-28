import { useEffect, useState } from "react";
import api from "../services/api";

function Findings() {
    const [findings, setFindings] = useState([]);
    const [search, setSearch] = useState("");
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchFindings();
    }, []);

    const fetchFindings = async () => {
        try {
            const response = await api.get("/findings");
            setFindings(response.data);
        } catch (error) {
            console.error("Error fetching findings:", error);
        } finally {
            setLoading(false);
        }
    };

    const filteredFindings = findings.filter((finding) =>
        `${finding.vulnerability} ${finding.severity} ${finding.status}`
            .toLowerCase()
            .includes(search.toLowerCase())
    );

    return (
        <div className="page">

            <div className="page-header">
                <div>
                    <h1>Security Findings</h1>
                    <p>Manage and track identified vulnerabilities.</p>
                </div>
            </div>

            <div className="card">

                <div className="table-header">
                    <h3>All Findings</h3>

                    <input
                        type="text"
                        placeholder="Search findings..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className="search-input"
                    />
                </div>

                {loading ? (
                    <p>Loading findings...</p>
                ) : filteredFindings.length === 0 ? (
                    <div className="empty-state">
                        <h3>No findings found</h3>
                        <p>
                            Add vulnerability findings from the VAPT assessment.
                        </p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">

                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Vulnerability</th>
                                    <th>Module</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                </tr>
                            </thead>

                            <tbody>
                                {filteredFindings.map((finding) => (
                                    <tr key={finding.id}>

                                        <td>#{finding.id}</td>

                                        <td>
                                            <strong>
                                                {finding.vulnerability}
                                            </strong>
                                        </td>

                                        <td>
                                            {finding.affected_module || "-"}
                                        </td>

                                        <td>
                                            <span
                                                className={`severity-badge ${finding.severity
                                                    ?.toLowerCase()
                                                    .replace(" ", "-")}`}
                                            >
                                                {finding.severity}
                                            </span>
                                        </td>

                                        <td>
                                            <span className="status-badge">
                                                {finding.status}
                                            </span>
                                        </td>

                                        <td>
                                            {finding.created_at
                                                ? new Date(
                                                    finding.created_at
                                                ).toLocaleDateString()
                                                : "-"}
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

export default Findings;