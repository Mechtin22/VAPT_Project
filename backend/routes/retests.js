const express = require("express");
const db = require("../config/db");

const router = express.Router();

router.get("/", async (req, res) => {

    try {

        const [rows] = await db.query(
            `SELECT
                r.*,
                f.vulnerability
             FROM retests r
             JOIN findings f
                ON r.finding_id = f.id
             ORDER BY r.tested_at DESC`
        );

        res.json(rows);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to retrieve retests"
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

        const allowed = [
            "Pass",
            "Fail",
            "Inconclusive"
        ];

        if (
            !finding_id ||
            !allowed.includes(result)
        ) {
            return res.status(400).json({
                error: "Invalid retest data"
            });
        }

        const [insert] = await db.execute(
            `INSERT INTO retests
            (
                finding_id,
                result,
                notes
            )
            VALUES (?, ?, ?)`,
            [
                Number(finding_id),
                result,
                notes || null
            ]
        );

        if (result === "Pass") {

            await db.execute(
                `UPDATE findings
                 SET status = 'Resolved'
                 WHERE id = ?`,
                [Number(finding_id)]
            );

        } else if (result === "Fail") {

            await db.execute(
                `UPDATE findings
                 SET status = 'Open'
                 WHERE id = ?`,
                [Number(finding_id)]
            );
        }

        res.status(201).json({
            message: "Retest recorded",
            id: insert.insertId
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to record retest"
        });
    }
});

module.exports = router;