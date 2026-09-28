import {
    useEffect,
    useState
} from "react";

import {
    Plus,
    ShieldCheck
} from "lucide-react";

import api from "../services/api";

function Assessments() {

    const [assessments, setAssessments] =
        useState([]);

    useEffect(() => {

        api.get("/assessments")
            .then(
                response =>
                    setAssessments(
                        response.data
                    )
            )
            .catch(
                console.error
            );

    }, []);

    return (

        <div>

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

                <button className="primary-btn">

                    <Plus size={18} />

                    New Assessment

                </button>

            </div>

            <div className="assessment-grid">

                {assessments.map(
                    assessment => (

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

                            <span
                                className="badge blue"
                            >
                                {
                                    assessment.status
                                }
                            </span>

                        </div>

                    )
                )}

            </div>

        </div>
    );
}

export default Assessments;