const express = require("express");
const router = express.Router();

const pool = require("../config/db");


// GET ALL FINDINGS
router.get("/", async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT
                f.id,
                f.assessment_id,
                f.vulnerability,
                f.affected_module,
                f.description,
                f.observed_result,
                f.impact,
                f.severity,
                f.mitigation,
                f.status,
                f.created_at,
                a.title AS assessment_title
            FROM findings f
            LEFT JOIN assessments a
                ON f.assessment_id = a.id
            ORDER BY f.created_at DESC
        `);

        res.json(rows);

    } catch (error) {
        console.error("Error fetching findings:", error);

        res.status(500).json({
            error: "Failed to fetch findings",
            message: error.message
        });
    }
});


// GET ONE FINDING
router.get("/:id", async (req, res) => {
    try {
        const [rows] = await pool.query(
            "SELECT * FROM findings WHERE id = ?",
            [req.params.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                error: "Finding not found"
            });
        }

        res.json(rows[0]);

    } catch (error) {
        console.error("Error fetching finding:", error);

        res.status(500).json({
            error: "Failed to fetch finding",
            message: error.message
        });
    }
});


// CREATE FINDING
router.post("/", async (req, res) => {
    try {
        const {
            assessment_id,
            vulnerability,
            affected_module,
            description,
            observed_result,
            impact,
            severity,
            mitigation,
            status
        } = req.body;

        const [result] = await pool.query(
            `
            INSERT INTO findings
            (
                assessment_id,
                vulnerability,
                affected_module,
                description,
                observed_result,
                impact,
                severity,
                mitigation,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
                assessment_id,
                vulnerability,
                affected_module,
                description,
                observed_result,
                impact,
                severity,
                mitigation,
                status || "Open"
            ]
        );

        res.status(201).json({
            message: "Finding created successfully",
            id: result.insertId
        });

    } catch (error) {
        console.error("Error creating finding:", error);

        res.status(500).json({
            error: "Failed to create finding",
            message: error.message
        });
    }
});


// UPDATE FINDING
router.put("/:id", async (req, res) => {
    try {
        const {
            vulnerability,
            affected_module,
            description,
            observed_result,
            impact,
            severity,
            mitigation,
            status
        } = req.body;

        await pool.query(
            `
            UPDATE findings
            SET
                vulnerability = ?,
                affected_module = ?,
                description = ?,
                observed_result = ?,
                impact = ?,
                severity = ?,
                mitigation = ?,
                status = ?
            WHERE id = ?
            `,
            [
                vulnerability,
                affected_module,
                description,
                observed_result,
                impact,
                severity,
                mitigation,
                status,
                req.params.id
            ]
        );

        res.json({
            message: "Finding updated successfully"
        });

    } catch (error) {
        console.error("Error updating finding:", error);

        res.status(500).json({
            error: "Failed to update finding",
            message: error.message
        });
    }
});


// DELETE FINDING
router.delete("/:id", async (req, res) => {
    try {
        await pool.query(
            "DELETE FROM findings WHERE id = ?",
            [req.params.id]
        );

        res.json({
            message: "Finding deleted successfully"
        });

    } catch (error) {
        console.error("Error deleting finding:", error);

        res.status(500).json({
            error: "Failed to delete finding",
            message: error.message
        });
    }
});


module.exports = router;