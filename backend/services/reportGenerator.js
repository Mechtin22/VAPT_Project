const PDFDocument = require("pdfkit");
const db = require("../config/db");

async function generateReport(
    assessmentId,
    res
) {

    const [assessments] =
        await db.execute(
            `SELECT *
             FROM assessments
             WHERE id = ?`,
            [assessmentId]
        );

    if (assessments.length === 0) {

        return res.status(404).json({
            error:
                "Assessment not found"
        });
    }

    const assessment =
        assessments[0];

    const [findings] =
        await db.execute(
            `SELECT *
             FROM findings
             WHERE assessment_id = ?
             ORDER BY id`,
            [assessmentId]
        );

    const [retests] =
        await db.execute(
            `SELECT
                r.*,
                f.vulnerability
             FROM retests r
             JOIN findings f
                ON r.finding_id = f.id
             JOIN assessments a
                ON f.assessment_id = a.id
             WHERE a.id = ?
             ORDER BY r.tested_at DESC`,
            [assessmentId]
        );

    const doc =
        new PDFDocument({
            size: "A4",
            margin: 50
        });

    res.setHeader(
        "Content-Type",
        "application/pdf"
    );

    res.setHeader(
        "Content-Disposition",
        `attachment; filename="VAPT-Report-${assessmentId}.pdf"`
    );

    doc.pipe(res);

    doc
        .fontSize(24)
        .text(
            "WEB APPLICATION SECURITY ASSESSMENT",
            {
                align: "center"
            }
        );

    doc.moveDown();

    doc
        .fontSize(13)
        .text(
            `Assessment: ${assessment.title}`
        )
        .text(
            `Target: ${assessment.target_url}`
        )
        .text(
            `Tester: ${assessment.tester || "N/A"}`
        )
        .text(
            `Status: ${assessment.status}`
        );

    doc.moveDown();

    doc
        .fontSize(17)
        .text("Executive Summary");

    doc.moveDown();

    doc
        .fontSize(11)
        .text(
            `The assessment identified ${findings.length} recorded security finding(s) during testing of the authorized local DVWA environment.`
        );

    doc.moveDown();

    doc
        .fontSize(17)
        .text("Findings");

    findings.forEach(
        (finding, index) => {

            doc.moveDown();

            doc
                .fontSize(14)
                .text(
                    `${index + 1}. ${finding.vulnerability}`
                );

            doc
                .fontSize(10)
                .text(
                    `Severity: ${finding.severity}`
                )
                .text(
                    `Status: ${finding.status}`
                )
                .text(
                    `Module: ${finding.affected_module || "N/A"}`
                );

            doc.moveDown(0.5);

            doc.text(
                `Description: ${finding.description || "N/A"}`
            );

            doc.text(
                `Observed Result: ${finding.observed_result || "N/A"}`
            );

            doc.text(
                `Impact: ${finding.impact || "N/A"}`
            );

            doc.text(
                `Mitigation: ${finding.mitigation || "N/A"}`
            );
        }
    );

    doc.moveDown();

    doc
        .fontSize(17)
        .text("Retesting");

    retests.forEach(
        (retest) => {

            doc.moveDown();

            doc
                .fontSize(10)
                .text(
                    `${retest.vulnerability} — ${retest.result}`
                )
                .text(
                    retest.notes || ""
                );
        }
    );

    doc.moveDown();

    doc
        .fontSize(9)
        .text(
            "This report documents testing performed only against the authorized local assessment environment."
        );

    doc.end();
}

module.exports =
    generateReport;