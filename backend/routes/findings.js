const express = require("express");
const db = require("../config/db");

const router = express.Router();

const allowedSeverities = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info"
];

const allowedStatuses = [
    "Open",
    "Resolved",
    "In Progress"
];

router.get("/", async (req, res) => {
    try {
        const [rows] = await db.query(`
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

router.get("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid finding ID"
            });
        }

        const [rows] = await db.query(
            `
            SELECT
                f.*,
                a.title AS assessment_title
            FROM findings f
            LEFT JOIN assessments a
                ON f.assessment_id = a.id
            WHERE f.id = ?
            `,
            [id]
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

        if (!assessment_id || !vulnerability || !severity) {
            return res.status(400).json({
                error:
                    "Assessment, vulnerability and severity are required"
            });
        }

        if (!allowedSeverities.includes(severity)) {
            return res.status(400).json({
                error: "Invalid severity"
            });
        }

        const findingStatus = status || "Open";

        if (!allowedStatuses.includes(findingStatus)) {
            return res.status(400).json({
                error: "Invalid status"
            });
        }

        const [assessment] = await db.query(
            `
            SELECT id
            FROM assessments
            WHERE id = ?
            `,
            [Number(assessment_id)]
        );

        if (assessment.length === 0) {
            return res.status(400).json({
                error: "Assessment does not exist"
            });
        }

        const [result] = await db.execute(
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
                Number(assessment_id),
                vulnerability.trim(),
                affected_module?.trim() || null,
                description?.trim() || null,
                observed_result?.trim() || null,
                impact?.trim() || null,
                severity,
                mitigation?.trim() || null,
                findingStatus
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

router.put("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid finding ID"
            });
        }

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

        if (!vulnerability || !severity) {
            return res.status(400).json({
                error:
                    "Vulnerability and severity are required"
            });
        }

        if (!allowedSeverities.includes(severity)) {
            return res.status(400).json({
                error: "Invalid severity"
            });
        }

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({
                error: "Invalid status"
            });
        }

        const [result] = await db.execute(
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
                vulnerability.trim(),
                affected_module?.trim() || null,
                description?.trim() || null,
                observed_result?.trim() || null,
                impact?.trim() || null,
                severity,
                mitigation?.trim() || null,
                status,
                id
            ]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                error: "Finding not found"
            });
        }

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

router.delete("/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id < 1) {
            return res.status(400).json({
                error: "Invalid finding ID"
            });
        }

        const [result] = await db.execute(
            `
            DELETE FROM findings
            WHERE id = ?
            `,
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                error: "Finding not found"
            });
        }

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