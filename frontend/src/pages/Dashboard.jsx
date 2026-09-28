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

import StatCard
    from "../components/StatCard";

function Dashboard() {

    const [findings, setFindings] =
        useState([]);

    useEffect(() => {

        api.get("/findings")
            .then(
                response =>
                    setFindings(
                        response.data
                    )
            )
            .catch(
                error =>
                    console.error(error)
            );

    }, []);

    const high =
        findings.filter(
            f =>
                f.severity === "High" ||
                f.severity === "Critical"
        ).length;

    const medium =
        findings.filter(
            f =>
                f.severity === "Medium"
        ).length;

    const low =
        findings.filter(
            f =>
                f.severity === "Low" ||
                f.severity === "Info"
        ).length;

    const resolved =
        findings.filter(
            f =>
                f.status === "Resolved"
        ).length;

    const chartData = [
        {
            name: "High",
            value: high
        },
        {
            name: "Medium",
            value: medium
        },
        {
            name: "Low",
            value: low
        }
    ];

    const COLORS = [
        "#ef4444",
        "#f59e0b",
        "#38bdf8"
    ];

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

            <div className="stats-grid">

                <StatCard
                    title="Total Findings"
                    value={findings.length}
                    subtitle="Recorded"
                    icon={Bug}
                />

                <StatCard
                    title="High / Critical"
                    value={high}
                    subtitle="Attention"
                    icon={AlertTriangle}
                />

                <StatCard
                    title="Resolved"
                    value={resolved}
                    subtitle="Retested"
                    icon={CheckCircle}
                />

                <StatCard
                    title="Assessment"
                    value="Active"
                    subtitle="In Progress"
                    icon={Shield}
                />

            </div>

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
                                        (_, index) => (

                                            <Cell
                                                key={index}
                                                fill={
                                                    COLORS[
                                                        index
                                                    ]
                                                }
                                            />

                                        )
                                    )}

                                </Pie>

                                <Tooltip />

                            </PieChart>

                        </ResponsiveContainer>

                    </div>

                </div>

                <div className="panel">

                    <div className="panel-header">

                        <div>
                            <h3>
                                Assessment Progress
                            </h3>

                            <p>
                                Current project status
                            </p>
                        </div>

                        <span className="badge blue">
                            ACTIVE
                        </span>

                    </div>

                    <div className="progress-list">

                        <Progress
                            name="Environment Setup"
                            value={100}
                        />

                        <Progress
                            name="Reconnaissance"
                            value={100}
                        />

                        <Progress
                            name="Burp Analysis"
                            value={100}
                        />

                        <Progress
                            name="SQL Injection"
                            value={100}
                        />

                        <Progress
                            name="Other Vulnerabilities"
                            value={25}
                        />

                        <Progress
                            name="Retesting"
                            value={0}
                        />

                    </div>

                </div>

            </div>

            <div className="panel">

                <div className="panel-header">

                    <div>

                        <h3>
                            Recent Findings
                        </h3>

                        <p>
                            Latest recorded
                            security observations
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
                                .map(finding => (

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
                                                finding.affected_module ||
                                                "—"
                                            }
                                        </td>

                                        <td>

                                            <span
                                                className={
                                                    `severity ${finding.severity.toLowerCase()}`
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

                                ))}

                        </tbody>

                    </table>

                    {findings.length === 0 && (

                        <div className="empty">

                            <Shield
                                size={32}
                            />

                            <p>
                                No findings
                                recorded yet.
                            </p>

                        </div>

                    )}

                </div>

            </div>

        </div>
    );
}

function Progress({
    name,
    value
}) {

    return (

        <div className="progress-item">

            <div className="progress-label">

                <span>
                    {name}
                </span>

                <strong>
                    {value}%
                </strong>

            </div>

            <div className="progress-track">

                <div
                    className="progress-fill"
                    style={{
                        width: `${value}%`
                    }}
                />

            </div>

        </div>
    );
}

export default Dashboard;