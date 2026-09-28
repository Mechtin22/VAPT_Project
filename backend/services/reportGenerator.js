const PDFDocument = require("pdfkit");
const db = require("../config/db");

async function generateReport(
    assessmentId,
    res
) {
    const [assessments] =
        await db.execute(
            `
            SELECT *
            FROM assessments
            WHERE id = ?
            `,
            [assessmentId]
        );

    if (assessments.length === 0) {
        return res.status(404).json({
            error: "Assessment not found"
        });
    }

    const assessment =
        assessments[0];

    const [findings] =
        await db.execute(
            `
            SELECT *
            FROM findings
            WHERE assessment_id = ?
            ORDER BY id
            `,
            [assessmentId]
        );

    const [retests] =
        await db.execute(
            `
            SELECT
                r.*,
                f.vulnerability
            FROM retests r
            JOIN findings f
                ON r.finding_id = f.id
            WHERE f.assessment_id = ?
            ORDER BY r.tested_at DESC
            `,
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
        .fontSize(22)
        .text(
            "WEB APPLICATION SECURITY ASSESSMENT",
            {
                align: "center"
            }
        );

    doc.moveDown();

    doc
        .fontSize(12)
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

    if (assessment.scope_description) {
        doc
            .moveDown()
            .text(
                `Scope: ${assessment.scope_description}`
            );
    }

    doc.moveDown();

    doc
        .fontSize(16)
        .text("Executive Summary");

    doc.moveDown();

    doc
        .fontSize(10)
        .text(
            `The assessment contains ${findings.length} recorded security finding(s).`
        );

    doc.moveDown();

    doc
        .fontSize(16)
        .text("Findings");

    if (findings.length === 0) {
        doc
            .fontSize(10)
            .text(
                "No findings have been recorded."
            );
    }

    findings.forEach(
        (finding, index) => {
            doc.moveDown();

            doc
                .fontSize(13)
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
                )
                .text(
                    `Description: ${finding.description || "N/A"}`
                )
                .text(
                    `Observed Result: ${finding.observed_result || "N/A"}`
                )
                .text(
                    `Impact: ${finding.impact || "N/A"}`
                )
                .text(
                    `Mitigation: ${finding.mitigation || "N/A"}`
                );
        }
    );

    doc.moveDown();

    doc
        .fontSize(16)
        .text("Retesting");

    if (retests.length === 0) {
        doc
            .fontSize(10)
            .text(
                "No retesting records have been recorded."
            );
    }

    retests.forEach(
        (retest) => {
            doc.moveDown();

            doc
                .fontSize(10)
                .text(
                    `${retest.vulnerability} — ${retest.result}`
                );

            if (retest.tested_at) {
                doc.text(
                    `Tested: ${new Date(
                        retest.tested_at
                    ).toLocaleString()}`
                );
            }

            if (retest.notes) {
                doc.text(
                    `Notes: ${retest.notes}`
                );
            }
        }
    );

    doc.moveDown();

    doc
        .fontSize(9)
        .text(
            "This report documents testing performed against the authorized local assessment environment."
        );

    doc.end();
}

module.exports = generateReport;