import {
    useEffect,
    useState
} from "react";

import {
    Plus,
    ShieldCheck,
    X
} from "lucide-react";

import api from "../services/api";

function Assessments() {
    const [assessments, setAssessments] =
        useState([]);

    const [showForm, setShowForm] =
        useState(false);

    const [form, setForm] = useState({
        title: "",
        target_url: "http://localhost/DVWA",
        scope_description: "",
        tester: ""
    });

    const [loading, setLoading] =
        useState(true);

    const loadAssessments = async () => {
        try {
            const response =
                await api.get("/assessments");

            setAssessments(response.data);
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadAssessments();
    }, []);

    const handleChange = (event) => {
        setForm({
            ...form,
            [event.target.name]:
                event.target.value
        });
    };

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

                setShowForm(false);

                await loadAssessments();
            } catch (error) {
                console.error(error);

                alert(
                    error.response?.data?.error ||
                    "Failed to create assessment"
                );
            }
        };

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

                <button
                    className="primary-btn"
                    onClick={() =>
                        setShowForm(true)
                    }
                >
                    <Plus size={18} />
                    New Assessment
                </button>
            </div>

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
                                setShowForm(false)
                            }
                        >
                            <X size={16} />
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
                            placeholder="Assessment title"
                            value={form.title}
                            onChange={
                                handleChange
                            }
                            required
                        />

                        <input
                            name="target_url"
                            placeholder="Target URL"
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
                            placeholder="Tester name"
                            value={form.tester}
                            onChange={
                                handleChange
                            }
                        />

                        <textarea
                            name="scope_description"
                            placeholder="Scope description"
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

            {loading ? (
                <div className="panel">
                    Loading assessments...
                </div>
            ) : (
                <div className="assessment-grid">
                    {assessments.map(
                        (assessment) => (
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
                            </div>
                        )
                    )}

                    {assessments.length ===
                        0 && (
                        <div className="panel">
                            No assessments
                            created yet.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default Assessments;