const express = require("express");
const db = require("../config/db");

const router = express.Router();

router.get("/", async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT
                id,
                title,
                target_url,
                scope_description,
                tester,
                status,
                started_at,
                created_at
            FROM assessments
            ORDER BY started_at DESC
        `);

        res.json(rows);
    } catch (error) {
        console.error("Error fetching assessments:", error);

        res.status(500).json({
            error: "Unable to retrieve assessments",
            message: error.message
        });
    }
});

router.get("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid assessment ID"
            });
        }

        const [rows] = await db.query(
            `
            SELECT *
            FROM assessments
            WHERE id = ?
            `,
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error("Error fetching assessment:", error);

        res.status(500).json({
            error: "Unable to retrieve assessment",
            message: error.message
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
            `
            INSERT INTO assessments
            (
                title,
                target_url,
                scope_description,
                tester,
                status
            )
            VALUES (?, ?, ?, ?, 'In Progress')
            `,
            [
                title.trim(),
                target_url.trim(),
                scope_description?.trim() || null,
                tester?.trim() || null
            ]
        );

        res.status(201).json({
            message: "Assessment created successfully",
            id: result.insertId
        });
    } catch (error) {
        console.error("Error creating assessment:", error);

        res.status(500).json({
            error: "Unable to create assessment",
            message: error.message
        });
    }
});

router.delete("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid assessment ID"
            });
        }

        const [result] = await db.execute(
            `
            DELETE FROM assessments
            WHERE id = ?
            `,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        res.json({
            message: "Assessment deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting assessment:", error);

        res.status(500).json({
            error: "Unable to delete assessment",
            message: error.message
        });
    }
});

module.exports = router;