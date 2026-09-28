import {
    RefreshCcw
} from "lucide-react";

function Retesting() {

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
                        Track remediation
                        verification results.
                    </p>

                </div>

            </div>

            <div className="panel empty-large">

                <RefreshCcw size={42} />

                <h3>
                    Retest Workspace
                </h3>

                <p>
                    Record Pass, Fail or
                    Inconclusive results for
                    previously identified
                    findings.
                </p>

            </div>

        </div>
    );
}

export default Retesting;