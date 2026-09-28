const express = require("express");
const db = require("../config/db");

const router = express.Router();

const allowedResults = [
    "Pass",
    "Fail",
    "Inconclusive"
];

router.get("/", async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                r.id,
                r.finding_id,
                r.result,
                r.notes,
                r.tested_at,
                f.vulnerability,
                f.severity,
                f.status
            FROM retests r
            JOIN findings f
                ON r.finding_id = f.id
            ORDER BY r.tested_at DESC
        `);

        res.json(rows);
    } catch (error) {
        console.error(
            "Error fetching retests:",
            error
        );

        res.status(500).json({
            error:
                "Unable to retrieve retests"
        });
    }
});

router.post("/", async (req, res) => {
    try {
        const {
            finding_id,
            result,
            notes
        } = req.body;

        const findingId =
            Number(finding_id);

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
                error: "Invalid retest result"
            });
        }

        const [finding] =
            await db.query(
                `
                SELECT id
                FROM findings
                WHERE id = ?
                `,
                [findingId]
            );

        if (finding.length === 0) {
            return res.status(404).json({
                error: "Finding not found"
            });
        }

        const [insert] =
            await db.execute(
                `
                INSERT INTO retests
                (
                    finding_id,
                    result,
                    notes
                )
                VALUES (?, ?, ?)
                `,
                [
                    findingId,
                    result,
                    notes?.trim() || null
                ]
            );

        if (result === "Pass") {
            await db.execute(
                `
                UPDATE findings
                SET status = 'Resolved'
                WHERE id = ?
                `,
                [findingId]
            );
        }

        if (result === "Fail") {
            await db.execute(
                `
                UPDATE findings
                SET status = 'Open'
                WHERE id = ?
                `,
                [findingId]
            );
        }

        res.status(201).json({
            message:
                "Retest recorded successfully",
            id: insert.insertId
        });
    } catch (error) {
        console.error(
            "Error recording retest:",
            error
        );

        res.status(500).json({
            error:
                "Unable to record retest",
            message: error.message
        });
    }
});

module.exports = router;