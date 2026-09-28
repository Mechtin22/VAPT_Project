import {
    FileSearch
} from "lucide-react";

function Evidence() {

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
                        requests and scan
                        results for findings.
                    </p>

                </div>

            </div>

            <div className="panel empty-large">

                <FileSearch size={42} />

                <h3>
                    Evidence Workspace
                </h3>

                <p>
                    Select a finding to upload
                    and review its supporting
                    evidence.
                </p>

            </div>

        </div>
    );
}

export default Evidence;