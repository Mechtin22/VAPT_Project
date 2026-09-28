import {
    useEffect,
    useState
} from "react";

import {
    RefreshCcw
} from "lucide-react";

import api from "../services/api";

function Retesting() {
    const [findings, setFindings] =
        useState([]);

    const [retests, setRetests] =
        useState([]);

    const [findingId, setFindingId] =
        useState("");

    const [result, setResult] =
        useState("Pass");

    const [notes, setNotes] =
        useState("");

    const loadData = async () => {
        try {
            const [
                findingsResponse,
                retestsResponse
            ] = await Promise.all([
                api.get("/findings"),
                api.get("/retests")
            ]);

            setFindings(
                findingsResponse.data
            );

            setRetests(
                retestsResponse.data
            );
        } catch (error) {
            console.error(error);
        }
    };

    useEffect(() => {
        loadData();
    }, []);

    const recordRetest =
        async (event) => {
            event.preventDefault();

            if (!findingId) {
                alert(
                    "Select a finding."
                );
                return;
            }

            try {
                await api.post(
                    "/retests",
                    {
                        finding_id:
                            Number(findingId),
                        result,
                        notes
                    }
                );

                setFindingId("");
                setResult("Pass");
                setNotes("");

                await loadData();
            } catch (error) {
                console.error(error);

                alert(
                    error.response?.data?.error ||
                    "Failed to record retest"
                );
            }
        };

    return (
        <div>
            <div className="page-header">
                <div>
                    <p className="eyebrow">
                        VERIFICATION
                    </p>

                    <h2>
                        Retesting
                    </h2>

                    <p>
                        Verify whether
                        previously identified
                        vulnerabilities have
                        been remediated.
                    </p>
                </div>
            </div>

            <div className="panel">
                <h3>
                    Record Retest
                </h3>

                <form
                    onSubmit={
                        recordRetest
                    }
                    className="form-grid"
                >
                    <select
                        value={findingId}
                        onChange={(event) =>
                            setFindingId(
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
                        value={result}
                        onChange={(event) =>
                            setResult(
                                event.target.value
                            )
                        }
                    >
                        <option>
                            Pass
                        </option>
                        <option>
                            Fail
                        </option>
                        <option>
                            Inconclusive
                        </option>
                    </select>

                    <textarea
                        placeholder="Retest notes"
                        value={notes}
                        onChange={(event) =>
                            setNotes(
                                event.target.value
                            )
                        }
                        rows="4"
                    />

                    <button
                        className="primary-btn"
                        type="submit"
                    >
                        <RefreshCcw
                            size={17}
                        />
                        Record Retest
                    </button>
                </form>
            </div>

            <div className="panel">
                <h3>
                    Retest History
                </h3>

                {retests.length === 0 ? (
                    <div className="empty-large">
                        No retests recorded.
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>
                                        Finding
                                    </th>
                                    <th>
                                        Result
                                    </th>
                                    <th>
                                        Notes
                                    </th>
                                    <th>
                                        Tested
                                    </th>
                                </tr>
                            </thead>

                            <tbody>
                                {retests.map(
                                    (retest) => (
                                        <tr
                                            key={
                                                retest.id
                                            }
                                        >
                                            <td>
                                                {
                                                    retest.vulnerability
                                                }
                                            </td>

                                            <td>
                                                {
                                                    retest.result
                                                }
                                            </td>

                                            <td>
                                                {
                                                    retest.notes ||
                                                    "-"
                                                }
                                            </td>

                                            <td>
                                                {new Date(
                                                    retest.tested_at
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

export default Retesting;