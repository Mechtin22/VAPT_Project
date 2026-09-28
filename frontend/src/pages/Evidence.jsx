import {
    useEffect,
    useState
} from "react";

import {
    FileSearch,
    Upload
} from "lucide-react";

import api from "../services/api";

function Evidence() {
    const [findings, setFindings] =
        useState([]);

    const [selectedFinding, setSelectedFinding] =
        useState("");

    const [file, setFile] =
        useState(null);

    const [type, setType] =
        useState("Screenshot");

    const [description, setDescription] =
        useState("");

    const [evidence, setEvidence] =
        useState([]);

    const loadFindings = async () => {
        try {
            const response =
                await api.get("/findings");

            setFindings(response.data);
        } catch (error) {
            console.error(error);
        }
    };

    const loadEvidence =
        async (findingId) => {
            if (!findingId) {
                setEvidence([]);
                return;
            }

            try {
                const response =
                    await api.get(
                        `/evidence/${findingId}`
                    );

                setEvidence(response.data);
            } catch (error) {
                console.error(error);
            }
        };

    useEffect(() => {
        loadFindings();
    }, []);

    useEffect(() => {
        loadEvidence(
            selectedFinding
        );
    }, [selectedFinding]);

    const uploadEvidence =
        async (event) => {
            event.preventDefault();

            if (!selectedFinding || !file) {
                alert(
                    "Select a finding and evidence file."
                );
                return;
            }

            const formData =
                new FormData();

            formData.append(
                "evidence",
                file
            );

            formData.append(
                "evidence_type",
                type
            );

            formData.append(
                "description",
                description
            );

            try {
                await api.post(
                    `/evidence/${selectedFinding}`,
                    formData,
                    {
                        headers: {
                            "Content-Type":
                                "multipart/form-data"
                        }
                    }
                );

                setFile(null);
                setDescription("");

                await loadEvidence(
                    selectedFinding
                );

                alert(
                    "Evidence uploaded successfully."
                );
            } catch (error) {
                console.error(error);

                alert(
                    error.response?.data?.error ||
                    "Evidence upload failed"
                );
            }
        };

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        EVIDENCE MANAGEMENT
                    </p>

                    <h2>
                        Security Evidence
                    </h2>

                    <p>
                        Store screenshots,
                        HTTP data and scan
                        results.
                    </p>
                </div>
            </div>

            <div className="panel">
                <h3>
                    Upload Evidence
                </h3>

                <form
                    onSubmit={
                        uploadEvidence
                    }
                    className="form-grid"
                >
                    <select
                        value={
                            selectedFinding
                        }
                        onChange={(event) =>
                            setSelectedFinding(
                                event.target.value
                            )
                        }
                    >
                        <option value="">
                            Select finding
                        </option>

                        {findings.map(
                            (finding) => (
                                <option
                                    key={
                                        finding.id
                                    }
                                    value={
                                        finding.id
                                    }
                                >
                                    #{finding.id} —{" "}
                                    {
                                        finding.vulnerability
                                    }
                                </option>
                            )
                        )}
                    </select>

                    <select
                        value={type}
                        onChange={(event) =>
                            setType(
                                event.target.value
                            )
                        }
                    >
                        <option>
                            Screenshot
                        </option>
                        <option>
                            HTTP Request
                        </option>
                        <option>
                            HTTP Response
                        </option>
                        <option>
                            Scan Result
                        </option>
                        <option>
                            Other
                        </option>
                    </select>

                    <input
                        type="file"
                        accept=".png,.jpg,.jpeg,.pdf,.txt"
                        onChange={(event) =>
                            setFile(
                                event.target.files?.[0] ||
                                null
                            )
                        }
                    />

                    <textarea
                        placeholder="Evidence description"
                        value={description}
                        onChange={(event) =>
                            setDescription(
                                event.target.value
                            )
                        }
                        rows="4"
                    />

                    <button
                        className="primary-btn"
                        type="submit"
                    >
                        <Upload size={17} />
                        Upload Evidence
                    </button>
                </form>
            </div>

            <div className="panel">
                <h3>
                    Evidence Records
                </h3>

                {evidence.length === 0 ? (
                    <div className="empty-large">
                        <FileSearch
                            size={42}
                        />

                        <p>
                            No evidence
                            uploaded for this
                            finding.
                        </p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>
                                        Type
                                    </th>
                                    <th>
                                        File
                                    </th>
                                    <th>
                                        Description
                                    </th>
                                    <th>
                                        Date
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {evidence.map(
                                    (item) => (
                                        <tr
                                            key={
                                                item.id
                                            }
                                        >
                                            <td>
                                                {
                                                    item.evidence_type
                                                }
                                            </td>

                                            <td>
                                                <a
                                                    href={`http://localhost:5000/uploads/${item.file_path}`}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                >
                                                    View
                                                </a>
                                            </td>

                                            <td>
                                                {
                                                    item.description ||
                                                    "-"
                                                }
                                            </td>

                                            <td>
                                                {new Date(
                                                    item.created_at
                                                ).toLocaleString()}
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

export default Evidence;