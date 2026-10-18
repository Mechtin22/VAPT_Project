const PDFDocument = require("pdfkit");
const db = require("../config/db");
const path = require("path");

// =========================================================
// HELPERS
// =========================================================

function safeText(value, limit = 2500) {
    if (
        value === null ||
        value === undefined ||
        String(value).trim() === ""
    ) {
        return "N/A";
    }

    return String(value).slice(0, limit);
}

function formatDate(value) {
    if (!value) return "N/A";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
}

function fileName(filePath) {
    if (!filePath) return "N/A";

    return path.basename(
        String(filePath).replace(/\\/g, "/")
    );
}

function countStatus(items, expected) {
    return items.filter(
        (item) => item.result === expected
    ).length;
}

function countSeverity(items, expected) {
    return items.filter(
        (item) =>
            String(item.severity).toLowerCase() ===
            expected.toLowerCase()
    ).length;
}

function countByCategory(items) {
    return new Set(
        items.map((item) => item.vulnerability)
    ).size;
}


// =========================================================
// DEDUPLICATE OBSERVED RESULTS
// =========================================================

function compactObservedResult(finding, occurrences) {
    if (
        finding.vulnerability ===
        "Missing Security Headers"
    ) {
        const counts = new Map();

        for (const occurrence of occurrences) {
            const name =
                occurrence.detected_vulnerability ||
                "Missing security header";

            counts.set(
                name,
                (counts.get(name) || 0) + 1
            );
        }

        if (counts.size > 0) {
            return Array.from(
                counts.entries()
            )
                .map(
                    ([name, count]) =>
                        `${name}: ${count} affected response(s).`
                )
                .join("\n");
        }
    }

    const lines = Array.from(
        new Set(
            String(finding.observed_result || "")
                .split(/\r?\n/)
                .map((line) => line.trim())
                .filter(Boolean)
        )
    );

    if (lines.length === 0) {
        return "No observed result recorded.";
    }

    const limit = 8;
    const visible = lines.slice(0, limit);

    if (lines.length > limit) {
        visible.push(
            `${lines.length - limit} additional distinct observation(s) are stored in the application.`
        );
    }

    return visible.join("\n");
}


// =========================================================
// SUMMARIZE OCCURRENCES
// =========================================================

function compactOccurrences(finding, occurrences) {
    if (occurrences.length === 0) {
        return [
            "No individual occurrences were recorded."
        ];
    }

    // Missing security headers are grouped by affected location.
    // Each location retains the names of its missing headers.
    if (
        finding.vulnerability ===
        "Missing Security Headers"
    ) {
        const locations = new Map();

        for (const occurrence of occurrences) {
            const location =
                occurrence.affected_module ||
                "Unknown location";

            if (!locations.has(location)) {
                locations.set(location, new Set());
            }

            locations.get(location).add(
                occurrence.detected_vulnerability ||
                "Missing security header"
            );
        }

        const entries = Array.from(
            locations.entries()
        );

        const lines = entries
            .slice(0, 8)
            .map(([location, headers]) => {
                return (
                    `- ${location} — ` +
                    Array.from(headers).join(", ")
                );
            });

        if (entries.length > 8) {
            lines.push(
                `${entries.length - 8} additional unique location(s) are stored in the application.`
            );
        }

        lines.unshift(
            `${occurrences.length} occurrence(s) across ${entries.length} unique location(s).`
        );

        return lines;
    }

    // For other findings, remove exact duplicate descriptions
    // but retain the individual occurrence IDs.
    const uniqueOccurrences = [];
    const seen = new Set();

    for (const occurrence of occurrences) {
        const key = [
            occurrence.affected_module || "",
            occurrence.parameter_name || "",
            occurrence.detected_vulnerability || ""
        ].join("|");

        if (seen.has(key)) {
            continue;
        }

        seen.add(key);
        uniqueOccurrences.push(occurrence);
    }

    const lines = uniqueOccurrences
        .slice(0, 8)
        .map((occurrence) => {
            const location =
                occurrence.affected_module ||
                "Unknown location";

            const parameter = occurrence.parameter_name
                ? `; Parameter: ${occurrence.parameter_name}`
                : "";

            return (
                `- Occurrence #${occurrence.id}: ` +
                `${location}${parameter}`
            );
        });

    if (uniqueOccurrences.length > 8) {
        lines.push(
            `${uniqueOccurrences.length - 8} additional unique occurrence(s) are stored in the application.`
        );
    }

    lines.unshift(
        `${occurrences.length} recorded occurrence(s), ${uniqueOccurrences.length} unique displayed location/parameter combination(s).`
    );

    return lines;
}


// =========================================================
// GENERATE ASSESSMENT REPORT
// =========================================================

async function generateReport(assessmentId, res) {
    // -----------------------------------------------------
    // ASSESSMENT
    // -----------------------------------------------------

    const [assessmentRows] = await db.execute(
        `
            SELECT *
            FROM assessments
            WHERE id = ?
        `,
        [assessmentId]
    );

    if (!assessmentRows.length) {
        return res.status(404).json({
            error: "Assessment not found"
        });
    }

    const assessment = assessmentRows[0];

    // -----------------------------------------------------
    // SEQUENTIAL ASSESSMENT DISPLAY NUMBER
    // -----------------------------------------------------
    // Use the same ordering as the Assessments page.
    // The frontend numbers this list from 1 to N, oldest first.
    // Keep the database ID unchanged for internal operations.
    // -----------------------------------------------------

    const [orderedAssessments] = await db.execute(
        `
            SELECT id
            FROM assessments
            ORDER BY started_at DESC
        `
    );

    const assessmentIndex = orderedAssessments.findIndex(
        (item) => Number(item.id) === Number(assessment.id)
    );

    const displayAssessmentNumber = assessmentIndex >= 0
        ? orderedAssessments.length - assessmentIndex
        : 1;


    // -----------------------------------------------------
    // SCAN HISTORY
    // -----------------------------------------------------

    const [scans] = await db.execute(
        `
            SELECT
                id,
                assessment_id,
                scan_number,
                status,
                started_at,
                completed_at,
                pages_scanned,
                findings_detected,
                findings_created,
                duration_ms
            FROM scan_runs
            WHERE assessment_id = ?
            ORDER BY scan_number ASC
        `,
        [assessmentId]
    );


    // -----------------------------------------------------
    // FINDINGS
    // -----------------------------------------------------

    const [findings] = await db.execute(
        `
            SELECT
                f.*,
                sr.scan_number
            FROM findings f

            LEFT JOIN scan_runs sr
                ON sr.id = f.scan_id

            WHERE f.assessment_id = ?

            ORDER BY
                COALESCE(sr.scan_number, 0),
                f.id
        `,
        [assessmentId]
    );


    // -----------------------------------------------------
    // OCCURRENCES
    // -----------------------------------------------------

    const [occurrences] = await db.execute(
        `
            SELECT
                o.id,
                o.finding_id,
                o.detected_vulnerability,
                o.affected_module,
                o.parameter_name
            FROM finding_occurrences o

            INNER JOIN findings f
                ON f.id = o.finding_id

            WHERE f.assessment_id = ?

            ORDER BY
                f.id,
                o.id
        `,
        [assessmentId]
    );


    // -----------------------------------------------------
    // EVIDENCE REFERENCES
    // -----------------------------------------------------

    const [evidenceRows] = await db.execute(
        `
            SELECT
                e.id,
                e.finding_id,

                COALESCE(
                    e.scan_id,
                    f.scan_id
                ) AS effective_scan_id,

                e.occurrence_id,
                e.evidence_type,
                e.file_path,
                e.description,
                e.created_at

            FROM evidence e

            INNER JOIN findings f
                ON f.id = e.finding_id

            WHERE f.assessment_id = ?

            ORDER BY
                f.id,
                e.id
        `,
        [assessmentId]
    );


    // -----------------------------------------------------
    // RETEST HISTORY
    // -----------------------------------------------------

    const [retests] = await db.execute(
        `
            SELECT
                r.id,
                r.finding_id,
                r.result,
                r.notes,
                r.tested_at,

                f.vulnerability,
                f.severity

            FROM retests r

            INNER JOIN findings f
                ON f.id = r.finding_id

            WHERE f.assessment_id = ?

            ORDER BY r.tested_at DESC
        `,
        [assessmentId]
    );


    // -----------------------------------------------------
    // GROUP DATA BY FINDING
    // -----------------------------------------------------

    const occurrencesByFinding = new Map();
    const evidenceByFinding = new Map();
    const retestsByFinding = new Map();

    for (const item of occurrences) {
        if (!occurrencesByFinding.has(item.finding_id)) {
            occurrencesByFinding.set(
                item.finding_id,
                []
            );
        }

        occurrencesByFinding
            .get(item.finding_id)
            .push(item);
    }

    for (const item of evidenceRows) {
        if (!evidenceByFinding.has(item.finding_id)) {
            evidenceByFinding.set(
                item.finding_id,
                []
            );
        }

        evidenceByFinding
            .get(item.finding_id)
            .push(item);
    }

    for (const item of retests) {
        if (!retestsByFinding.has(item.finding_id)) {
            retestsByFinding.set(
                item.finding_id,
                []
            );
        }

        retestsByFinding
            .get(item.finding_id)
            .push(item);
    }

    const scanById = new Map(
        scans.map((scan) => [scan.id, scan])
    );


    // -----------------------------------------------------
    // SUMMARY STATISTICS
    // -----------------------------------------------------

    const uniqueCategories =
        countByCategory(findings);

    const totalOccurrences =
        occurrences.length;

    const totalEvidence =
        evidenceRows.length;

    const totalRetests =
        retests.length;

    const completedScans = scans.filter(
        (scan) => scan.status === "Completed"
    ).length;

    const severityCounts = {
        Critical: countSeverity(findings, "Critical"),
        High: countSeverity(findings, "High"),
        Medium: countSeverity(findings, "Medium"),
        Low: countSeverity(findings, "Low"),
        Info: countSeverity(findings, "Info")
    };


    // -----------------------------------------------------
    // CREATE PDF
    // -----------------------------------------------------

    const doc = new PDFDocument({
        size: "A4",
        margin: 48,
        bufferPages: true,
        info: {
            Title: `VAPT Report - ${assessment.title}`,
            Subject:
                "Web Application Penetration Testing using DVWA",
            Author: assessment.tester || "VAPT Project"
        }
    });

    res.setHeader(
        "Content-Type",
        "application/pdf"
    );

    // The file name uses the sequential display number too.
    // The report API request still uses the database ID.
    res.setHeader(
        "Content-Disposition",
        `attachment; filename="VAPT-Report-${displayAssessmentNumber}.pdf"`
    );

    doc.pipe(res);

    const contentWidth =
        doc.page.width -
        doc.page.margins.left -
        doc.page.margins.right;


    // -----------------------------------------------------
    // FORMATTING HELPERS
    // -----------------------------------------------------

    function section(title) {
        doc.moveDown(0.7);

        doc
            .fillColor("#17365D")
            .font("Helvetica-Bold")
            .fontSize(14)
            .text(title, {
                width: contentWidth
            });

        doc
            .fillColor("#000000")
            .font("Helvetica")
            .fontSize(9);

        doc.moveDown(0.25);
    }

    function paragraph(value) {
        doc
            .font("Helvetica")
            .fontSize(9)
            .fillColor("#222222")
            .text(
                safeText(value),
                {
                    width: contentWidth,
                    lineGap: 2
                }
            );

        doc.moveDown(0.25);
    }

    function label(name, value) {
        doc
            .font("Helvetica-Bold")
            .fontSize(9)
            .text(`${name}:`, {
                continued: true,
                width: contentWidth
            });

        doc
            .font("Helvetica")
            .fontSize(9)
            .text(` ${safeText(value)}`, {
                width: contentWidth
            });
    }

    function divider() {
        doc.moveDown(0.25);

        doc
            .strokeColor("#B8C7D9")
            .lineWidth(0.5)
            .moveTo(
                doc.page.margins.left,
                doc.y
            )
            .lineTo(
                doc.page.width -
                    doc.page.margins.right,
                doc.y
            )
            .stroke();

        doc.moveDown(0.35);
    }


    // =====================================================
    // 1. COVER AND ASSESSMENT DETAILS
    // =====================================================

    doc
        .font("Helvetica-Bold")
        .fontSize(21)
        .fillColor("#17365D")
        .text(
            "WEB APPLICATION SECURITY",
            {
                align: "center",
                width: contentWidth
            }
        );

    doc
        .fontSize(18)
        .text(
            "ASSESSMENT REPORT",
            {
                align: "center",
                width: contentWidth
            }
        );

    doc.moveDown(0.5);

    doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#444444")
        .text(
            "Web Application Penetration Testing using DVWA",
            {
                align: "center",
                width: contentWidth
            }
        );

    doc.moveDown(1.5);

    section("Assessment Details");

    // Display the sequential assessment number, not the DB ID.
    label("Assessment Number", displayAssessmentNumber);
    label("Title", assessment.title);
    label("Target URL", assessment.target_url);
    label("Tester", assessment.tester);
    label("Status", assessment.status);
    label("Created At", formatDate(assessment.created_at));
    label("Scope", assessment.scope_description);


    // =====================================================
    // 2. EXECUTIVE SUMMARY
    // =====================================================

    section("Executive Summary");

    paragraph(
        `This assessment contains ${scans.length} scan run(s), ${findings.length} finding record(s), ${uniqueCategories} distinct finding category name(s), ${totalOccurrences} occurrence record(s), ${totalEvidence} evidence record(s), and ${totalRetests} retest record(s).`
    );

    label("Scan Runs", scans.length);
    label("Completed Scans", completedScans);
    label("Finding Records", findings.length);
    label("Distinct Category Names", uniqueCategories);
    label("Occurrences", totalOccurrences);
    label("Evidence Records", totalEvidence);
    label("Retest Records", totalRetests);

    doc.moveDown(0.25);

    label("Critical Finding Records", severityCounts.Critical);
    label("High Finding Records", severityCounts.High);
    label("Medium Finding Records", severityCounts.Medium);
    label("Low Finding Records", severityCounts.Low);
    label("Informational Finding Records", severityCounts.Info);

    paragraph(
        "A finding record is associated with an individual scan. The same vulnerability category may appear in multiple scans. Occurrences refer to individual affected locations or observations; these counts do not independently prove exploitability."
    );


    // =====================================================
    // 3. SCAN HISTORY
    // =====================================================

    section("Scan History");

    if (scans.length === 0) {
        paragraph(
            "No scan history is recorded for this assessment."
        );
    }

    for (const scan of scans) {
        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .fillColor("#17365D")
            .text(
                `Scan #${scan.scan_number}`,
                {
                    width: contentWidth
                }
            );

        doc
            .font("Helvetica")
            .fontSize(9)
            .fillColor("#000000");

        label("Status", scan.status);
        label("Started", formatDate(scan.started_at));
        label("Completed", formatDate(scan.completed_at));
        label("Pages / Resources", scan.pages_scanned);
        label("Raw Observations", scan.findings_detected);
        label("Finding Records Created", scan.findings_created);
        label("Duration", `${scan.duration_ms || 0} ms`);

        divider();
    }


    // =====================================================
    // 4. FINDINGS
    // =====================================================

    section("Findings and Affected Locations");

    if (findings.length === 0) {
        paragraph(
            "No findings have been recorded."
        );
    }

    const MAX_EVIDENCE_PER_FINDING = 6;
    const MAX_RETESTS_PER_FINDING = 3;

    for (
        let index = 0;
        index < findings.length;
        index += 1
    ) {
        const finding = findings[index];

        const findingOccurrences =
            occurrencesByFinding.get(finding.id) || [];

        const findingEvidence =
            evidenceByFinding.get(finding.id) || [];

        const findingRetests =
            retestsByFinding.get(finding.id) || [];

        const scan = finding.scan_id
            ? scanById.get(finding.scan_id)
            : null;


        // -------------------------------------------------
        // FINDING SUMMARY
        // -------------------------------------------------

        doc.moveDown(0.4);

        doc
            .font("Helvetica-Bold")
            .fontSize(12)
            .fillColor("#17365D")
            .text(
                `${index + 1}. ${safeText(finding.vulnerability, 200)}`,
                {
                    width: contentWidth
                }
            );

        doc
            .font("Helvetica")
            .fontSize(9)
            .fillColor("#000000");

        label("Finding ID", finding.id);

        label(
            "Scan",
            scan
                ? `#${scan.scan_number}`
                : "Legacy / manual finding"
        );

        label("Severity", finding.severity);
        label("Status", finding.status);
        label("Affected Module", finding.affected_module);
        label("Description", finding.description);

        // Use the compact observed-result summary.
        paragraph(
            `Observed Result:\n${compactObservedResult(
                finding,
                findingOccurrences
            )}`
        );

        label("Impact", finding.impact);
        label("Mitigation", finding.mitigation);


        // -------------------------------------------------
        // OCCURRENCES
        // -------------------------------------------------

        doc.moveDown(0.25);

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(
                `Affected Occurrences (${findingOccurrences.length})`,
                {
                    width: contentWidth
                }
            );

        doc
            .font("Helvetica")
            .fontSize(9);

        for (const line of compactOccurrences(
            finding,
            findingOccurrences
        )) {
            doc.text(
                line,
                {
                    width: contentWidth
                }
            );
        }


        // -------------------------------------------------
        // EVIDENCE REFERENCES
        // -------------------------------------------------

        doc.moveDown(0.3);

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(
                `Evidence References (${findingEvidence.length})`,
                {
                    width: contentWidth
                }
            );

        doc
            .font("Helvetica")
            .fontSize(9);

        if (!findingEvidence.length) {
            paragraph(
                "No evidence records are attached to this finding."
            );
        } else {
            const listedEvidence =
                findingEvidence.slice(
                    0,
                    MAX_EVIDENCE_PER_FINDING
                );

            for (const evidence of listedEvidence) {
                const evidenceScan =
                    evidence.effective_scan_id
                        ? scanById.get(
                            evidence.effective_scan_id
                        )
                        : null;

                label("Evidence ID", evidence.id);
                label("Type", evidence.evidence_type);

                label(
                    "Scan",
                    evidenceScan
                        ? `#${evidenceScan.scan_number}`
                        : "Not linked to a scan"
                );

                label("Occurrence ID", evidence.occurrence_id);
                label("File", fileName(evidence.file_path));
                label("Description", evidence.description);
            }

            const remainingEvidence =
                findingEvidence.length -
                listedEvidence.length;

            if (remainingEvidence > 0) {
                paragraph(
                    `${remainingEvidence} additional evidence record(s) are stored in the application.`
                );
            }
        }


        // -------------------------------------------------
        // RETEST HISTORY
        // -------------------------------------------------

        doc.moveDown(0.3);

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(
                `Retest History (${findingRetests.length})`,
                {
                    width: contentWidth
                }
            );

        doc
            .font("Helvetica")
            .fontSize(9);

        if (!findingRetests.length) {
            paragraph(
                "No retest records are attached to this finding."
            );
        } else {
            const listedRetests =
                findingRetests.slice(
                    0,
                    MAX_RETESTS_PER_FINDING
                );

            for (const retest of listedRetests) {
                doc.text(
                    `- ${retest.result} - ${formatDate(retest.tested_at)}`,
                    {
                        width: contentWidth
                    }
                );

                if (retest.notes) {
                    paragraph(
                        `Notes: ${retest.notes}`
                    );
                }
            }

            const remainingRetests =
                findingRetests.length -
                listedRetests.length;

            if (remainingRetests > 0) {
                paragraph(
                    `${remainingRetests} additional retest record(s) are available in the application.`
                );
            }
        }

        divider();
    }


    // =====================================================
    // 5. RETEST SUMMARY
    // =====================================================

    section("Overall Retesting Summary");

    if (retests.length === 0) {
        paragraph(
            "No retest records have been recorded."
        );
    } else {
        label("Total Retest Records", retests.length);
        label("Pass", countStatus(retests, "Pass"));
        label("Fail", countStatus(retests, "Fail"));
        label(
            "Inconclusive",
            countStatus(retests, "Inconclusive")
        );
    }


    // =====================================================
    // 6. METHODOLOGY AND LIMITATIONS
    // =====================================================

    section("Methodology and Limitations");

    paragraph(
        "The assessment was performed against the configured local DVWA lab using the scanner checks implemented in this project."
    );

    paragraph(
        "A reflected input marker does not by itself prove executable Cross-Site Scripting. SQL error signatures should be reviewed to confirm that they result from user-controlled SQL input. The current scanner does not cover every DVWA vulnerability class."
    );

    paragraph(
        "Evidence references identify records and files stored by the application. This PDF lists references; it does not embed every evidence file."
    );

    paragraph(
        "Finding and occurrence counts should not be interpreted as independently confirmed exploitable vulnerabilities without further validation."
    );


    // =====================================================
    // 7. FOOTERS
    // =====================================================

    const pageRange = doc.bufferedPageRange();
    const totalPages = pageRange.count;

    for (
        let pageIndex = pageRange.start;
        pageIndex < pageRange.start + pageRange.count;
        pageIndex += 1
    ) {
        doc.switchToPage(pageIndex);

        const originalBottomMargin =
            doc.page.margins.bottom;

        // Keep footer within the existing page boundary.
        doc.page.margins.bottom = 10;

        const footerY =
            doc.page.height - 28;

        doc
            .font("Helvetica")
            .fontSize(8)
            .fillColor("#666666")
            .text(
                `VAPT Report | Assessment #${displayAssessmentNumber}`,
                doc.page.margins.left,
                footerY,
                {
                    width: contentWidth / 2,
                    lineBreak: false
                }
            );

        doc.text(
            `Page ${pageIndex + 1} of ${totalPages}`,
            doc.page.width -
                doc.page.margins.right -
                100,
            footerY,
            {
                width: 100,
                align: "right",
                lineBreak: false
            }
        );

        doc.page.margins.bottom =
            originalBottomMargin;
    }

    doc.end();
}


// =========================================================
// EXPORT
// =========================================================

module.exports = generateReport;