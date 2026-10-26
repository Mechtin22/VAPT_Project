const express = require("express");
const db = require("../config/db");

const router = express.Router();

const allowedResults = [
    "Pass",
    "Fail",
    "Inconclusive"
];

const allowedMethods = [
    "Manual",
    "Automated"
];


// =========================================================
// GET /api/retests
// Returns retest history with original finding and scan context.
// =========================================================

router.get("/", async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                r.id,
                r.finding_id,
                r.retest_scan_id,
                r.method,
                r.result,
                r.notes,
                r.tested_at,

                f.assessment_id,
                f.scan_id AS original_scan_id,
                f.vulnerability,
                f.affected_module,
                f.severity,
                f.status AS finding_status,

                a.title AS assessment_title,

                original_scan.scan_number
                    AS original_scan_number,

                retest_scan.scan_number
                    AS retest_scan_number,

                retest_scan.status
                    AS retest_scan_status

            FROM retests r

            INNER JOIN findings f
                ON r.finding_id = f.id

            LEFT JOIN assessments a
                ON f.assessment_id = a.id

            LEFT JOIN scan_runs original_scan
                ON f.scan_id = original_scan.id

            LEFT JOIN scan_runs retest_scan
                ON r.retest_scan_id = retest_scan.id

            ORDER BY r.tested_at DESC, r.id DESC
        `);

        return res.json(rows);
    } catch (error) {
        console.error(
            "Error fetching retests:",
            error
        );

        return res.status(500).json({
            error: "Unable to retrieve retests",
            message: error.message
        });
    }
});


// =========================================================
// POST /api/retests
//
// Body:
// {
//   "finding_id": 12,
//   "result": "Pass",
//   "notes": "The issue was manually validated.",
//   "method": "Manual",
//   "retest_scan_id": null
// }
//
// retest_scan_id is optional for manual retesting.
// Automated results must link to a completed scan.
// =========================================================

router.post("/", async (req, res) => {
    let connection;
    let transactionStarted = false;

    try {
        const {
            finding_id,
            result,
            notes
        } = req.body;

        const findingId = Number(finding_id);

        if (
            !Number.isInteger(findingId) ||
            findingId < 1
        ) {
            return res.status(400).json({
                error: "Invalid finding ID"
            });
        }

        if (!allowedResults.includes(result)) {
            return res.status(400).json({
                error:
                    "Invalid retest result. Use Pass, Fail, or Inconclusive."
            });
        }

        if (
            notes !== undefined &&
            notes !== null &&
            typeof notes !== "string"
        ) {
            return res.status(400).json({
                error: "Retest notes must be text."
            });
        }

        if (typeof notes === "string" && notes.length > 10000) {
            return res.status(400).json({
                error: "Retest notes cannot exceed 10000 characters."
            });
        }

        const requestedScanId =
            req.body.retest_scan_id === undefined ||
            req.body.retest_scan_id === null ||
            req.body.retest_scan_id === ""
                ? null
                : Number(req.body.retest_scan_id);

        if (
            requestedScanId !== null &&
            (
                !Number.isInteger(requestedScanId) ||
                requestedScanId < 1
            )
        ) {
            return res.status(400).json({
                error: "Invalid retest scan ID."
            });
        }

        const method =
            req.body.method ||
            (requestedScanId !== null
                ? "Automated"
                : "Manual");

        if (!allowedMethods.includes(method)) {
            return res.status(400).json({
                error: "Invalid retest method."
            });
        }

        if (
            method === "Automated" &&
            requestedScanId === null
        ) {
            return res.status(400).json({
                error:
                    "Automated retests must reference a completed retest scan."
            });
        }

        connection = await db.getConnection();

        await connection.beginTransaction();
        transactionStarted = true;

        // Lock the finding so that its status cannot be changed
        // concurrently while the retest result is being recorded.
        const [findingRows] = await connection.query(
            `
                SELECT
                    id,
                    assessment_id,
                    scan_id,
                    status
                FROM findings
                WHERE id = ?
                FOR UPDATE
            `,
            [findingId]
        );

        if (findingRows.length === 0) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(404).json({
                error: "Finding not found."
            });
        }

        const finding = findingRows[0];

        // If the user supplied a scan, verify that it belongs to
        // this finding's assessment and has completed successfully.
        if (requestedScanId !== null) {
            const [scanRows] = await connection.query(
                `
                    SELECT
                        id,
                        assessment_id,
                        scan_number,
                        status
                    FROM scan_runs
                    WHERE id = ?
                    FOR UPDATE
                `,
                [requestedScanId]
            );

            if (scanRows.length === 0) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(404).json({
                    error: "Retest scan not found."
                });
            }

            const retestScan = scanRows[0];

            if (
                Number(retestScan.assessment_id) !==
                Number(finding.assessment_id)
            ) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(400).json({
                    error:
                        "The retest scan must belong to the same assessment as the finding."
                });
            }

            if (
                String(retestScan.status).toLowerCase() !==
                "completed"
            ) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(400).json({
                    error:
                        "Only a completed scan can be linked to a retest."
                });
            }

            if (
                finding.scan_id !== null &&
                Number(finding.scan_id) === requestedScanId
            ) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(400).json({
                    error:
                        "The original finding scan cannot be used as its own retest scan."
                });
            }
        }

        // Keep the selected result, scan link and method together.
        const [insertResult] = await connection.execute(
            `
                INSERT INTO retests
                (
                    finding_id,
                    retest_scan_id,
                    method,
                    result,
                    notes
                )
                VALUES (?, ?, ?, ?, ?)
            `,
            [
                findingId,
                requestedScanId,
                method,
                result,
                typeof notes === "string"
                    ? notes.trim() || null
                    : null
            ]
        );

        // Status changes happen in the same transaction as the retest.
        // Inconclusive deliberately preserves the current finding status.
        if (result === "Pass") {
            await connection.execute(
                `
                    UPDATE findings
                    SET status = 'Resolved'
                    WHERE id = ?
                `,
                [findingId]
            );
        } else if (result === "Fail") {
            await connection.execute(
                `
                    UPDATE findings
                    SET status = 'Open'
                    WHERE id = ?
                `,
                [findingId]
            );
        }

        await connection.commit();
        transactionStarted = false;

        return res.status(201).json({
            message: "Retest recorded successfully.",

            retest: {
                id: insertResult.insertId,
                finding_id: findingId,
                retest_scan_id: requestedScanId,
                method,
                result,
                notes:
                    typeof notes === "string"
                        ? notes.trim() || null
                        : null,
                previous_status: finding.status,
                new_status:
                    result === "Pass"
                        ? "Resolved"
                        : result === "Fail"
                            ? "Open"
                            : finding.status
            }
        });
    } catch (error) {
        if (connection && transactionStarted) {
            try {
                await connection.rollback();
            } catch {
                // Preserve the original error.
            }
        }

        console.error(
            "Error recording retest:",
            error
        );

        return res.status(500).json({
            error: "Unable to record retest",
            message: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

module.exports = router;