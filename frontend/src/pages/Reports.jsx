import {
    useEffect,
    useState
} from "react";

import {
    FileText,
    Download
} from "lucide-react";

import api from "../services/api";

function Reports() {
    const [assessments, setAssessments] =
        useState([]);

    const [assessmentId, setAssessmentId] =
        useState("");

    useEffect(() => {
        api.get("/assessments")
            .then((response) => {
                setAssessments(
                    response.data
                );

                if (
                    response.data.length > 0
                ) {
                    setAssessmentId(
                        String(
                            response.data[0].id
                        )
                    );
                }
            })
            .catch((error) =>
                console.error(error)
            );
    }, []);

    const downloadReport = () => {
        if (!assessmentId) {
            alert(
                "Select an assessment."
            );
            return;
        }

        window.open(
            `http://localhost:5000/api/reports/${assessmentId}`,
            "_blank"
        );
    };

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        REPORTING
                    </p>

                    <h2>
                        Security Reports
                    </h2>

                    <p>
                        Generate structured
                        assessment reports.
                    </p>
                </div>
            </div>

            <div className="report-card">
                <div className="report-icon">
                    <FileText size={30} />
                </div>

                <div className="report-content">
                    <h3>
                        VAPT Assessment Report
                    </h3>

                    <p>
                        Generate findings,
                        mitigations and
                        retesting results.
                    </p>

                    <select
                        value={assessmentId}
                        onChange={(event) =>
                            setAssessmentId(
                                event.target.value
                            )
                        }
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
                </div>

                <button
                    className="primary-btn"
                    onClick={
                        downloadReport
                    }
                >
                    <Download size={18} />
                    Generate PDF
                </button>
            </div>
        </div>
    );
}

export default Reports;