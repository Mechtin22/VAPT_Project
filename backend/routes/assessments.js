const express = require("express");
const db = require("../config/db");

const router = express.Router();

router.get("/", async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT *
             FROM assessments
             ORDER BY started_at DESC`
        );

        res.json(rows);
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Unable to retrieve assessments"
        });
    }
});

router.post("/", async (req, res) => {
    try {
        const {
            title,
            target_url,
            scope_description,
            tester
        } = req.body;

        if (!title || !target_url) {
            return res.status(400).json({
                error: "Title and target URL are required"
            });
        }

        const [result] = await db.execute(
            `INSERT INTO assessments
            (
                title,
                target_url,
                scope_description,
                tester,
                status
            )
            VALUES (?, ?, ?, ?, 'In Progress')`,
            [
                title,
                target_url,
                scope_description || null,
                tester || null
            ]
        );

        res.status(201).json({
            message: "Assessment created",
            id: result.insertId
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Unable to create assessment"
        });
    }
});

module.exports = router;