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

                    if (
                        response.data.length > 0
                    ) {

                        setAssessmentId(
                            String(
                                response.data[0].id
                            )
                        );

                    }

                } catch (error) {

                    console.error(
                        "Failed to load assessments:",
                        error
                    );

                }

            };


        loadAssessments();

    }, []);


    const downloadReport = () => {

        if (!assessmentId) {

            alert(
                "Select an assessment."
            );

            return;

        }


        const reportUrl =
            `${api.defaults.baseURL}/reports/${assessmentId}`;


        window.open(
            reportUrl,
            "_blank",
            "noopener,noreferrer"
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

                    <FileText
                        size={30}
                    />

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
                        value={
                            assessmentId
                        }
                        onChange={
                            (event) =>
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
                    disabled={
                        !assessmentId
                    }
                >

                    <Download
                        size={18}
                    />

                    Generate PDF

                </button>

            </div>

        </div>

    );
}


export default Reports;