const express = require("express");
const { URL } = require("url");

const db = require("../config/db");

const {
    scanTarget
} = require("../services/scanner");

const router = express.Router();


// =========================================================
// DVWA-ONLY TARGET VALIDATION
// =========================================================

function isLocalDvwaTarget(value) {
    try {
        const url = new URL(value);

        return (
            ["http:", "https:"].includes(url.protocol) &&

            ["localhost", "127.0.0.1"].includes(
                url.hostname.toLowerCase()
            ) &&

            /^\/dvwa\/?$/i.test(url.pathname) &&

            !url.username &&
            !url.password &&
            !url.search &&
            !url.hash
        );
    } catch {
        return false;
    }
}


// =========================================================
// SEVERITY RANKING
// =========================================================

const severityRank = {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Info: 1
};


function highestSeverity(items) {
    return items.reduce(
        (highest, item) =>
            (severityRank[item.severity] || 0) >
            (severityRank[highest] || 0)
                ? item.severity
                : highest,

        "Info"
    );
}


// =========================================================
// FINDING CATEGORY NORMALIZATION
// =========================================================

function getCategory(vulnerability) {
    if (!vulnerability) {
        return "Unknown";
    }

    if (
        /^Missing .* header$/i.test(
            vulnerability
        )
    ) {
        return "Missing Security Headers";
    }

    return vulnerability;
}


// =========================================================
// EXTRACT PARAMETER NAME
// =========================================================

function extractParameter(affectedModule) {
    const match =
        typeof affectedModule === "string"
            ? affectedModule.match(
                /\[([^\]]+)\]\s*$/
            )
            : null;

    return match ? match[1] : null;
}


// =========================================================
// GROUP FINDINGS BY CATEGORY
// =========================================================

function groupFindings(findings) {
    const groups = new Map();

    for (const finding of findings) {
        const category = getCategory(
            finding.vulnerability
        );

        if (!groups.has(category)) {
            groups.set(category, []);
        }

        groups.get(category).push(finding);
    }

    return Array.from(
        groups,
        ([category, items]) => ({
            category,
            items,
            severity: highestSeverity(items)
        })
    );
}


// =========================================================
// CREATE A SCAN RUN
// =========================================================

async function createScanRun(assessmentId) {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        const [rows] = await connection.query(
            `
                SELECT
                    COALESCE(MAX(scan_number), 0) + 1
                        AS next_scan
                FROM scan_runs
                WHERE assessment_id = ?
            `,
            [assessmentId]
        );

        const scanNumber =
            Number(rows[0].next_scan);

        const [result] = await connection.execute(
            `
                INSERT INTO scan_runs
                (
                    assessment_id,
                    scan_number,
                    status
                )
                VALUES (?, ?, 'Running')
            `,
            [
                assessmentId,
                scanNumber
            ]
        );

        await connection.commit();

        return {
            scanId: result.insertId,
            scanNumber
        };
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
}


// =========================================================
// COMPLETE A SCAN
// =========================================================

async function completeScan(scanId, summary) {
    await db.execute(
        `
            UPDATE scan_runs
            SET
                status = 'Completed',
                completed_at = CURRENT_TIMESTAMP,
                pages_scanned = ?,
                findings_detected = ?,
                findings_created = ?,
                duration_ms = ?
            WHERE id = ?
        `,
        [
            summary.pages_scanned,
            summary.findings_detected,
            summary.findings_created,
            summary.duration_ms,
            scanId
        ]
    );
}


// =========================================================
// MARK A SCAN AS FAILED
// =========================================================

async function failScan(scanId) {
    try {
        await db.execute(
            `
                UPDATE scan_runs
                SET
                    status = 'Failed',
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [scanId]
        );
    } catch {
        // Preserve the original scan error.
    }
}


// =========================================================
// BUILD UNIQUE TEXT
// =========================================================

function uniqueText(items, field) {
    return Array.from(
        new Set(
            items
                .map((item) => item[field])
                .filter(Boolean)
        )
    ).join("\n");
}


// =========================================================
// BUILD CATEGORY DESCRIPTION
// =========================================================

function buildDescription(group) {
    if (
        group.category ===
        "Missing Security Headers"
    ) {
        return (
            "One or more recommended HTTP security " +
            "headers are missing from scanned DVWA pages. " +
            "Individual missing headers are recorded " +
            "as occurrences."
        );
    }

    return uniqueText(
        group.items,
        "description"
    );
}


// =========================================================
// BUILD AFFECTED MODULE SUMMARY
// =========================================================

function buildAffectedModule(group) {
    return (
        `${group.items.length} ` +
        "affected location(s)"
    );
}


// =========================================================
// INSERT A CATEGORY-LEVEL FINDING
// =========================================================

async function createCategoryFinding(
    assessmentId,
    scanId,
    group
) {
    const description =
        buildDescription(group);

    const observedResult =
        uniqueText(
            group.items,
            "observed_result"
        );

    const impact =
        uniqueText(
            group.items,
            "impact"
        );

    const affectedModule =
        buildAffectedModule(group);

    const [insertResult] = await db.execute(
        `
            INSERT INTO findings
            (
                assessment_id,
                scan_id,
                vulnerability,
                affected_module,
                description,
                observed_result,
                impact,
                severity,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
            assessmentId,
            scanId,
            group.category,
            affectedModule,
            description,
            observedResult,
            impact,
            group.severity,
            "Open"
        ]
    );

    return {
        findingId: insertResult.insertId,
        description,
        observedResult,
        impact,
        affectedModule
    };
}


// =========================================================
// INSERT INDIVIDUAL FINDING OCCURRENCES
// =========================================================

async function createOccurrences(
    findingId,
    items
) {
    for (const item of items) {
        await db.execute(
            `
                INSERT INTO finding_occurrences
                (
                    finding_id,
                    detected_vulnerability,
                    affected_module,
                    parameter_name
                )
                VALUES (?, ?, ?, ?)
            `,
            [
                findingId,

                item.vulnerability ||
                    "Unknown",

                item.affected_module ||
                    null,

                extractParameter(
                    item.affected_module
                )
            ]
        );
    }
}


// =========================================================
// RUN AUTOMATED DVWA SCAN
// POST /api/scans/:assessmentId
// =========================================================

router.post(
    "/:assessmentId",
    async (req, res) => {
        const assessmentId =
            Number(req.params.assessmentId);

        if (
            !Number.isInteger(assessmentId) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error: "Invalid assessment ID"
            });
        }

        let scanId = null;

        try {
            // Load assessment.
            const [rows] = await db.query(
                `
                    SELECT
                        id,
                        title,
                        target_url
                    FROM assessments
                    WHERE id = ?
                `,
                [assessmentId]
            );

            if (!rows.length) {
                return res.status(404).json({
                    error: "Assessment not found"
                });
            }

            const assessment = rows[0];

            // Reject non-DVWA targets.
            if (
                !isLocalDvwaTarget(
                    assessment.target_url
                )
            ) {
                return res.status(400).json({
                    error:
                        "This DVWA-only scanner accepts only the local DVWA root URL, for example http://localhost/DVWA/."
                });
            }

            // Create a scan history record.
            const scan = await createScanRun(
                assessmentId
            );

            scanId = scan.scanId;

            console.log(
                `Starting Assessment #${assessmentId} - Scan #${scan.scanNumber}`
            );

            console.log(
                `Target: ${assessment.target_url}`
            );

            // Execute scanner.
            const started = Date.now();

            const result = await scanTarget(
                assessment.target_url
            );

            const durationMs =
                Date.now() - started;

            const rawFindings =
                Array.isArray(result.findings)
                    ? result.findings
                    : [];

            // Group observations into categories.
            const groups = groupFindings(
                rawFindings
            );

            const createdCategories = [];

            // Insert one parent finding per category.
            for (const group of groups) {
                if (!group.items.length) {
                    continue;
                }

                const finding =
                    await createCategoryFinding(
                        assessmentId,
                        scanId,
                        group
                    );

                // Store each affected page/parameter.
                await createOccurrences(
                    finding.findingId,
                    group.items
                );

                createdCategories.push({
                    id: finding.findingId,

                    vulnerability:
                        group.category,

                    severity:
                        group.severity,

                    status: "Open",

                    affected_module:
                        finding.affectedModule,

                    occurrence_count:
                        group.items.length,

                    description:
                        finding.description,

                    observed_result:
                        finding.observedResult,

                    impact:
                        finding.impact,

                    occurrences:
                        group.items.map((item) => ({
                            detected_vulnerability:
                                item.vulnerability,

                            affected_module:
                                item.affected_module,

                            parameter_name:
                                extractParameter(
                                    item.affected_module
                                )
                        }))
                });
            }

            // Save scan statistics.
            const summary = {
                pages_scanned:
                    Number(
                        result.pages_scanned || 0
                    ),

                findings_detected:
                    rawFindings.length,

                findings_created:
                    createdCategories.length,

                duration_ms:
                    durationMs
            };

            await completeScan(
                scanId,
                summary
            );

            await db.execute(
                `
                    UPDATE assessments
                    SET status = 'Completed'
                    WHERE id = ?
                `,
                [assessmentId]
            );

            console.log(
                `Assessment #${assessmentId} - Scan #${scan.scanNumber} completed`
            );

            console.log(
                `Pages: ${summary.pages_scanned}`
            );

            console.log(
                `Raw findings: ${summary.findings_detected}`
            );

            console.log(
                `Created findings: ${summary.findings_created}`
            );

            console.log(
                `Duration: ${summary.duration_ms} ms`
            );

            return res.json({
                message:
                    "Scan completed successfully",

                assessment_id:
                    assessmentId,

                scan_id:
                    scanId,

                scan_number:
                    scan.scanNumber,

                target_url:
                    assessment.target_url,

                authenticated:
                    result.authenticated ?? null,

                security_level:
                    result.security_level ?? null,

                pages_scanned:
                    summary.pages_scanned,

                html_pages_scanned:
                    Number(
                        result.html_pages_scanned || 0
                    ),

                // Retained for frontend compatibility.
                javascript_files_scanned:
                    Number(
                        result.javascript_files_scanned || 0
                    ),

                api_endpoints_discovered:
                    Number(
                        result.api_endpoints_discovered || 0
                    ),

                forms_discovered:
                    Number(
                        result.forms_discovered || 0
                    ),

                parameters_tested:
                    Number(
                        result.parameters_tested || 0
                    ),

                duration_ms:
                    summary.duration_ms,

                findings_detected:
                    summary.findings_detected,

                findings_created:
                    summary.findings_created,

                findings:
                    createdCategories,

                categories:
                    createdCategories
            });
        } catch (error) {
            console.error(
                "Scan error:",
                error
            );

            if (scanId) {
                await failScan(scanId);
            }

            return res.status(500).json({
                error: "Scan failed",
                message: error.message
            });
        }
    }
);


// =========================================================
// GET SCAN HISTORY
// GET /api/scans/:assessmentId
// =========================================================

router.get(
    "/:assessmentId",
    async (req, res) => {
        const assessmentId =
            Number(req.params.assessmentId);

        if (
            !Number.isInteger(assessmentId) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error: "Invalid assessment ID"
            });
        }

        try {
            // Load scan history.
            const [scans] = await db.query(
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
                    ORDER BY scan_number DESC
                `,
                [assessmentId]
            );

            // Load findings and their occurrences.
            const [rows] = await db.query(
                `
                    SELECT
                        f.id,
                        f.scan_id,
                        f.vulnerability,
                        f.description,
                        f.observed_result,
                        f.impact,
                        f.severity,
                        f.status,

                        o.id AS occurrence_id,
                        o.detected_vulnerability,
                        o.affected_module,
                        o.parameter_name

                    FROM findings f

                    LEFT JOIN finding_occurrences o
                        ON f.id = o.finding_id

                    WHERE f.assessment_id = ?

                    ORDER BY
                        f.id DESC,
                        o.id ASC
                `,
                [assessmentId]
            );

            // Build scan objects.
            const scanMap = new Map(
                scans.map((scan) => [
                    scan.id,
                    {
                        ...scan,
                        findings: []
                    }
                ])
            );

            const findingMap = new Map();

            for (const row of rows) {
                // Skip old findings not associated with a scan.
                if (!row.scan_id) {
                    continue;
                }

                let finding =
                    findingMap.get(row.id);

                if (!finding) {
                    finding = {
                        id: row.id,
                        scan_id: row.scan_id,
                        vulnerability: row.vulnerability,
                        description: row.description,
                        observed_result: row.observed_result,
                        impact: row.impact,
                        severity: row.severity,
                        status: row.status,
                        occurrences: []
                    };

                    findingMap.set(
                        row.id,
                        finding
                    );

                    const scan =
                        scanMap.get(row.scan_id);

                    if (scan) {
                        scan.findings.push(finding);
                    }
                }

                // Add an individual occurrence to its parent.
                if (row.occurrence_id) {
                    finding.occurrences.push({
                        id: row.occurrence_id,

                        detected_vulnerability:
                            row.detected_vulnerability,

                        affected_module:
                            row.affected_module,

                        parameter_name:
                            row.parameter_name
                    });
                }
            }

            return res.json(
                Array.from(scanMap.values())
            );
        } catch (error) {
            console.error(
                "Error loading scan history:",
                error
            );

            return res.status(500).json({
                error: "Failed to load scan history",
                message: error.message
            });
        }
    }
);


// =========================================================
// CLEAR ASSESSMENT SCAN HISTORY
// DELETE /api/scans/:assessmentId/history
// =========================================================

router.delete(
    "/:assessmentId/history",
    async (req, res) => {
        const assessmentId =
            Number(req.params.assessmentId);

        if (
            !Number.isInteger(assessmentId) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error: "Invalid assessment ID"
            });
        }

        try {
            // Linked findings and occurrences should cascade
            // when scan_runs is deleted.
            const [result] = await db.execute(
                `
                    DELETE FROM scan_runs
                    WHERE assessment_id = ?
                `,
                [assessmentId]
            );

            // Also remove legacy findings not connected to a scan.
            await db.execute(
                `
                    DELETE FROM findings
                    WHERE
                        assessment_id = ?
                        AND scan_id IS NULL
                `,
                [assessmentId]
            );

            return res.json({
                message:
                    "Scan history cleared successfully",

                assessment_id:
                    assessmentId,

                deleted_scans:
                    result.affectedRows
            });
        } catch (error) {
            console.error(
                "Error clearing scan history:",
                error
            );

            return res.status(500).json({
                error: "Failed to clear scan history",
                message: error.message
            });
        }
    }
);


// =========================================================
// EXPORT
// =========================================================

module.exports = router;