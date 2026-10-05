const express = require("express");

const db = require("../config/db");

const {
    scanTarget
} = require("../services/scanner");

const router = express.Router();


// =========================================================
// LOCAL LAB TARGET VALIDATION
// =========================================================

function isLocalLabTarget(value) {
    try {
        const url = new URL(value);

        return (
            ["http:", "https:"].includes(url.protocol) &&
            ["localhost", "127.0.0.1"].includes(url.hostname)
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


function highestSeverity(findings) {
    return findings.reduce(
        (highest, finding) => {
            const current =
                severityRank[finding.severity] || 0;

            const existing =
                severityRank[highest] || 0;

            return current > existing
                ? finding.severity
                : highest;
        },
        "Info"
    );
}


// =========================================================
// CATEGORY NORMALIZATION
// =========================================================

function getCategory(vulnerability) {
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
// EXTRACT PARAMETER
// =========================================================

function extractParameter(affectedModule) {
    if (!affectedModule) {
        return null;
    }

    const match =
        affectedModule.match(
            /\[([^\]]+)\]\s*$/
        );

    return match
        ? match[1]
        : null;
}


// =========================================================
// BUILD FINDING GROUPS
// =========================================================

function groupFindings(findings) {
    const groups = new Map();

    for (const finding of findings) {
        const category =
            getCategory(
                finding.vulnerability
            );

        if (!groups.has(category)) {
            groups.set(
                category,
                []
            );
        }

        groups
            .get(category)
            .push(finding);
    }

    return Array.from(
        groups.entries()
    ).map(
        ([category, items]) => ({
            category,
            items,
            severity:
                highestSeverity(items)
        })
    );
}


// =========================================================
// CREATE SCAN RUN
// =========================================================

async function createScanRun(assessmentId) {
    const connection =
        await db.getConnection();

    try {
        await connection.beginTransaction();

        const [
            rows
        ] = await connection.query(
            `
                SELECT
                    COALESCE(
                        MAX(scan_number),
                        0
                    ) + 1 AS next_scan
                FROM scan_runs
                WHERE assessment_id = ?
            `,
            [
                assessmentId
            ]
        );

        const scanNumber =
            Number(
                rows[0].next_scan
            );

        const [
            result
        ] = await connection.execute(
            `
                INSERT INTO scan_runs
                (
                    assessment_id,
                    scan_number,
                    status
                )
                VALUES
                (
                    ?,
                    ?,
                    'Running'
                )
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
// COMPLETE SCAN
// =========================================================

async function completeScan(
    scanId,
    result
) {
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
            result.pages_scanned,
            result.findings_detected,
            result.findings_created,
            result.duration_ms || 0,
            scanId
        ]
    );
}


// =========================================================
// FAIL SCAN
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
            [
                scanId
            ]
        );
    } catch {
        // Do not hide original scan error.
    }
}


// =========================================================
// RUN SCAN
// POST /api/scans/:assessmentId
// =========================================================

router.post(
    "/:assessmentId",
    async (req, res) => {

        const assessmentId =
            Number(
                req.params.assessmentId
            );

        if (
            !Number.isInteger(
                assessmentId
            ) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error:
                    "Invalid assessment ID"
            });
        }

        let scanId = null;

        try {

            // -------------------------------------------------
            // GET ASSESSMENT
            // -------------------------------------------------

            const [
                rows
            ] = await db.query(
                `
                    SELECT
                        id,
                        title,
                        target_url
                    FROM assessments
                    WHERE id = ?
                `,
                [
                    assessmentId
                ]
            );

            if (rows.length === 0) {
                return res.status(404).json({
                    error:
                        "Assessment not found"
                });
            }

            const assessment =
                rows[0];


            // -------------------------------------------------
            // SAFETY CHECK
            // -------------------------------------------------

            if (
                !isLocalLabTarget(
                    assessment.target_url
                )
            ) {
                return res.status(400).json({
                    error:
                        "This lab scanner is restricted to localhost/127.0.0.1 targets."
                });
            }


            // -------------------------------------------------
            // CREATE SCAN RUN
            // -------------------------------------------------

            const scan =
                await createScanRun(
                    assessmentId
                );

            scanId =
                scan.scanId;


            console.log(
                `Starting Assessment #${assessmentId} - Scan #${scan.scanNumber}`
            );

            console.log(
                `Target: ${assessment.target_url}`
            );


            // -------------------------------------------------
            // START TIMER
            // -------------------------------------------------

            const scanStartTime =
                Date.now();


            // -------------------------------------------------
            // RUN SCANNER
            // -------------------------------------------------

            const result =
                await scanTarget(
                    assessment.target_url
                );


            // -------------------------------------------------
            // CALCULATE DURATION
            // -------------------------------------------------

            const durationMs =
                Date.now() -
                scanStartTime;


            // -------------------------------------------------
            // GROUP FINDINGS
            // -------------------------------------------------

            const rawFindings =
                Array.isArray(
                    result.findings
                )
                    ? result.findings
                    : [];

            const groups =
                groupFindings(
                    rawFindings
                );


            let findingsCreated = 0;

            const createdCategories = [];


            // -------------------------------------------------
            // CREATE ONE FINDING PER CATEGORY
            // -------------------------------------------------

            for (
                const group of groups
            ) {

                const first =
                    group.items[0];


                const description =
                    group.category ===
                    "Missing Security Headers"
                        ? "One or more recommended HTTP security headers are missing across the scanned application."
                        : first.description;


                const observedResult =
                    group.items
                        .map(
                            (item) =>
                                item.observed_result
                        )
                        .filter(Boolean)
                        .join("\n");


                const impact =
                    group.items
                        .map(
                            (item) =>
                                item.impact
                        )
                        .filter(Boolean)
                        .filter(
                            (
                                value,
                                index,
                                array
                            ) =>
                                array.indexOf(
                                    value
                                ) === index
                        )
                        .join("\n");


                // ---------------------------------------------
                // CREATE CATEGORY FINDING
                // ---------------------------------------------

                const [
                    insertResult
                ] = await db.execute(
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
                        VALUES
                        (
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?
                        )
                    `,
                    [
                        assessmentId,
                        scanId,
                        group.category,
                        `${group.items.length} affected location(s)`,
                        description,
                        observedResult,
                        impact,
                        group.severity,
                        "Open"
                    ]
                );


                const findingId =
                    insertResult.insertId;


                findingsCreated += 1;


                // ---------------------------------------------
                // CREATE OCCURRENCES
                // ---------------------------------------------

                for (
                    const item of group.items
                ) {

                    await db.execute(
                        `
                            INSERT INTO finding_occurrences
                            (
                                finding_id,
                                detected_vulnerability,
                                affected_module,
                                parameter_name
                            )
                            VALUES
                            (
                                ?,
                                ?,
                                ?,
                                ?
                            )
                        `,
                        [
                            findingId,
                            item.vulnerability,
                            item.affected_module,
                            extractParameter(
                                item.affected_module
                            )
                        ]
                    );
                }


                // ---------------------------------------------
                // ADD TO RESPONSE
                // ---------------------------------------------

                createdCategories.push({
                    id: findingId,

                    vulnerability:
                        group.category,

                    severity:
                        group.severity,

                    status:
                        "Open",

                    affected_module:
                        `${group.items.length} affected location(s)`,

                    occurrence_count:
                        group.items.length,

                    description,

                    observed_result:
                        observedResult,

                    impact
                });
            }


            // -------------------------------------------------
            // BUILD SCAN SUMMARY
            // -------------------------------------------------

            const scanSummary = {

                pages_scanned:
                    Number(
                        result.pages_scanned || 0
                    ),

                findings_detected:
                    rawFindings.length,

                findings_created:
                    findingsCreated,

                duration_ms:
                    durationMs
            };


            // -------------------------------------------------
            // UPDATE SCAN
            // -------------------------------------------------

            await completeScan(
                scanId,
                scanSummary
            );


            // -------------------------------------------------
            // UPDATE ASSESSMENT
            // -------------------------------------------------

            await db.execute(
                `
                    UPDATE assessments
                    SET status = 'Completed'
                    WHERE id = ?
                `,
                [
                    assessmentId
                ]
            );


            console.log(
                `Assessment #${assessmentId} - Scan #${scan.scanNumber} completed`
            );


            // -------------------------------------------------
            // RESPONSE
            // -------------------------------------------------

            res.json({

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
                    scanSummary.pages_scanned,

                duration_ms:
                    scanSummary.duration_ms,

                findings_detected:
                    scanSummary.findings_detected,

                findings_created:
                    scanSummary.findings_created,

                // IMPORTANT:
                // Assessments.jsx expects "findings".
                findings:
                    createdCategories,

                // Keep categories too for compatibility.
                categories:
                    createdCategories
            });

        } catch (error) {

            console.error(
                "Scan error:",
                error
            );


            if (scanId) {
                await failScan(
                    scanId
                );
            }


            res.status(500).json({
                error:
                    "Scan failed",

                message:
                    error.message
            });
        }
    }
);


// =========================================================
// GET SCAN HISTORY FOR ASSESSMENT
// GET /api/scans/:assessmentId
// =========================================================

router.get(
    "/:assessmentId",
    async (req, res) => {

        const assessmentId =
            Number(
                req.params.assessmentId
            );


        if (
            !Number.isInteger(
                assessmentId
            ) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error:
                    "Invalid assessment ID"
            });
        }


        try {

            // -------------------------------------------------
            // GET SCANS
            // -------------------------------------------------

            const [
                scans
            ] = await db.query(
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
                [
                    assessmentId
                ]
            );


            // -------------------------------------------------
            // GET FINDINGS + OCCURRENCES
            // -------------------------------------------------

            const [
                findings
            ] = await db.query(
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

                    WHERE
                        f.assessment_id = ?

                    ORDER BY
                        f.id DESC,
                        o.id ASC
                `,
                [
                    assessmentId
                ]
            );


            // -------------------------------------------------
            // CREATE SCAN MAP
            // -------------------------------------------------

            const scanMap =
                new Map();


            for (
                const scan of scans
            ) {

                scanMap.set(
                    scan.id,
                    {
                        ...scan,
                        findings: []
                    }
                );
            }


            // -------------------------------------------------
            // CREATE FINDING MAP
            // -------------------------------------------------

            const findingMap =
                new Map();


            for (
                const row of findings
            ) {

                if (!row.scan_id) {
                    continue;
                }


                if (
                    !findingMap.has(
                        row.id
                    )
                ) {

                    const finding = {

                        id:
                            row.id,

                        scan_id:
                            row.scan_id,

                        vulnerability:
                            row.vulnerability,

                        description:
                            row.description,

                        observed_result:
                            row.observed_result,

                        impact:
                            row.impact,

                        severity:
                            row.severity,

                        status:
                            row.status,

                        occurrences: []
                    };


                    findingMap.set(
                        row.id,
                        finding
                    );


                    const scan =
                        scanMap.get(
                            row.scan_id
                        );


                    if (scan) {
                        scan.findings.push(
                            finding
                        );
                    }
                }


                // -------------------------------------------------
                // ADD OCCURRENCE
                // -------------------------------------------------

                if (
                    row.occurrence_id
                ) {

                    const finding =
                        findingMap.get(
                            row.id
                        );

                    if (finding) {
                        finding.occurrences.push({
                            id:
                                row.occurrence_id,

                            detected_vulnerability:
                                row.detected_vulnerability,

                            affected_module:
                                row.affected_module,

                            parameter_name:
                                row.parameter_name
                        });
                    }
                }
            }


            // -------------------------------------------------
            // RESPONSE
            // -------------------------------------------------

            res.json(
                Array.from(
                    scanMap.values()
                )
            );

        } catch (error) {

            console.error(
                "Error loading scan history:",
                error
            );


            res.status(500).json({
                error:
                    "Failed to load scan history",

                message:
                    error.message
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
            Number(
                req.params.assessmentId
            );


        if (
            !Number.isInteger(
                assessmentId
            ) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error:
                    "Invalid assessment ID"
            });
        }


        try {

            // -------------------------------------------------
            // DELETE SCAN RUNS
            //
            // Linked findings are deleted through
            // ON DELETE CASCADE.
            // -------------------------------------------------

            const [
                result
            ] = await db.execute(
                `
                    DELETE FROM scan_runs
                    WHERE assessment_id = ?
                `,
                [
                    assessmentId
                ]
            );


            // -------------------------------------------------
            // DELETE LEGACY FINDINGS
            //
            // These are findings created before scan history.
            // -------------------------------------------------

            await db.execute(
                `
                    DELETE FROM findings
                    WHERE
                        assessment_id = ?
                        AND scan_id IS NULL
                `,
                [
                    assessmentId
                ]
            );


            res.json({

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


            res.status(500).json({
                error:
                    "Failed to clear scan history",

                message:
                    error.message
            });
        }
    }
);


module.exports = router;