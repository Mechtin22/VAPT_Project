import {
    FileText,
    Download
} from "lucide-react";

function Reports() {

    function downloadReport() {

        window.open(
            "http://127.0.0.1:5000/api/reports/1",
            "_blank"
        );

    }

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
                        DVWA Security Assessment
                    </h3>

                    <p>
                        Generate the current
                        assessment findings,
                        mitigations and retest
                        status.
                    </p>

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