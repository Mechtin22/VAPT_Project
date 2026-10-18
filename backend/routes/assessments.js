const express = require("express");
const fs = require("fs/promises");
const path = require("path");

const db = require("../config/db");
const router = express.Router();

const uploadsRoot = path.resolve(__dirname, "..", "uploads");
const automaticRoot = path.resolve(
    uploadsRoot,
    "automatic-evidence"
);

function countRow(rows) {
    return Number(rows?.[0]?.total || 0);
}

function resolveUploadPath(storedPath) {
    if (!storedPath || typeof storedPath !== "string") {
        return null;
    }

    let value = storedPath.trim().replace(/\\/g, "/");

    if (!value) return null;

    if (/^https?:\/\//i.test(value)) {
        try {
            const parsed = new URL(value);
            const marker = "/uploads/";
            const index = parsed.pathname.indexOf(marker);

            if (index < 0) return null;

            value = decodeURIComponent(
                parsed.pathname.slice(index + marker.length)
            );
        } catch {
            return null;
        }
    } else if (value.startsWith("/uploads/")) {
        value = value.slice("/uploads/".length);
    } else if (value.startsWith("uploads/")) {
        value = value.slice("uploads/".length);
    }

    const resolved = path.isAbsolute(value)
        ? path.resolve(value)
        : path.resolve(uploadsRoot, value);

    const relative = path.relative(uploadsRoot, resolved);

    if (
        !relative ||
        relative === ".." ||
        relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relative)
    ) {
        return null;
    }

    return resolved;
}

function isInsideAutomaticEvidence(filePath) {
    const relative = path.relative(automaticRoot, filePath);

    return (
        relative === "" ||
        (
            relative !== ".." &&
            !relative.startsWith(`..${path.sep}`) &&
            !path.isAbsolute(relative)
        )
    );
}

async function countFilesRecursively(directory) {
    let entries;

    try {
        entries = await fs.readdir(directory, {
            withFileTypes: true
        });
    } catch (error) {
        if (error.code === "ENOENT") return 0;
        throw error;
    }

    let count = 0;

    for (const entry of entries) {
        const entryPath = path.join(directory, entry.name);

        if (entry.isDirectory()) {
            count += await countFilesRecursively(entryPath);
        } else if (entry.isFile()) {
            count += 1;
        }
    }

    return count;
}

async function cleanupAssessmentFiles(scanIds, evidenceRows) {
    const warnings = [];
    let deletedAutomaticFiles = 0;
    let deletedManualFiles = 0;

    // Remove only generated evidence folders belonging to this assessment.
    for (const scanId of scanIds) {
        const scanDirectory = path.resolve(
            automaticRoot,
            `scan-${Number(scanId)}`
        );

        if (path.dirname(scanDirectory) !== automaticRoot) {
            warnings.push({
                scan_id: scanId,
                message: "Unexpected automatic-evidence folder path."
            });
            continue;
        }

        try {
            const fileCount =
                await countFilesRecursively(scanDirectory);

            await fs.rm(scanDirectory, {
                recursive: true,
                force: true
            });

            deletedAutomaticFiles += fileCount;
        } catch (error) {
            warnings.push({
                scan_id: scanId,
                message: error.message
            });
        }
    }

    // Only delete uploaded files when no surviving evidence row references
    // the same path. Do not remove files outside backend/uploads.
    const candidateFiles = new Map();

    for (const evidence of evidenceRows) {
        const absolutePath = resolveUploadPath(
            evidence.file_path
        );

        if (!absolutePath) {
            if (evidence.file_path) {
                warnings.push({
                    evidence_id: evidence.id,
                    message: "Unsafe path; file was not deleted."
                });
            }
            continue;
        }

        if (isInsideAutomaticEvidence(absolutePath)) {
            continue;
        }

        candidateFiles.set(
            `${evidence.file_path}|${absolutePath}`,
            {
                storedPath: evidence.file_path,
                absolutePath
            }
        );
    }

    for (const item of candidateFiles.values()) {
        try {
            const [references] = await db.query(
                `
                    SELECT COUNT(*) AS total
                    FROM evidence
                    WHERE file_path = ?
                `,
                [item.storedPath]
            );

            if (countRow(references) > 0) continue;

            await fs.unlink(item.absolutePath);
            deletedManualFiles += 1;
        } catch (error) {
            if (error.code !== "ENOENT") {
                warnings.push({
                    file_path: item.storedPath,
                    message: error.message
                });
            }
        }
    }

    return {
        deleted_automatic_evidence_files: deletedAutomaticFiles,
        deleted_manual_upload_files: deletedManualFiles,
        file_cleanup_warnings: warnings
    };
}


// =========================================================
// GET ALL ASSESSMENTS
// =========================================================

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

        return res.json(rows);
    } catch (error) {
        console.error("Error fetching assessments:", error);

        return res.status(500).json({
            error: "Unable to retrieve assessments",
            message: error.message
        });
    }
});


// =========================================================
// GET ONE ASSESSMENT
// =========================================================

router.get("/:id", async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
            error: "Invalid assessment ID"
        });
    }

    try {
        const [rows] = await db.query(
            "SELECT * FROM assessments WHERE id = ?",
            [id]
        );

        if (!rows.length) {
            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        return res.json(rows[0]);
    } catch (error) {
        console.error("Error fetching assessment:", error);

        return res.status(500).json({
            error: "Unable to retrieve assessment",
            message: error.message
        });
    }
});


// =========================================================
// CREATE ASSESSMENT
// =========================================================

router.post("/", async (req, res) => {
    try {
        const {
            title,
            target_url,
            scope_description,
            tester
        } = req.body;

        if (!title?.trim() || !target_url?.trim()) {
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

        return res.status(201).json({
            message: "Assessment created successfully",
            id: result.insertId
        });
    } catch (error) {
        console.error("Error creating assessment:", error);

        return res.status(500).json({
            error: "Unable to create assessment",
            message: error.message
        });
    }
});


// =========================================================
// DELETE ASSESSMENT AND ASSOCIATED DATA
// DELETE /api/assessments/:id
// =========================================================

router.delete("/:id", async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({
            error: "Invalid assessment ID"
        });
    }

    let connection = null;
    let transactionStarted = false;

    let title = "";
    let scans = [];
    let evidenceRows = [];

    const counts = {
        deleted_scans: 0,
        deleted_findings: 0,
        deleted_occurrences: 0,
        deleted_evidence_records: 0,
        deleted_retests: 0,
        deleted_http_requests: 0
    };

    try {
        connection = await db.getConnection();
        await connection.beginTransaction();
        transactionStarted = true;

        const [assessmentRows] = await connection.query(
            `
                SELECT id, title
                FROM assessments
                WHERE id = ?
                FOR UPDATE
            `,
            [id]
        );

        if (!assessmentRows.length) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        title = assessmentRows[0].title;

        const [scanRows] = await connection.query(
            `
                SELECT id, scan_number, status
                FROM scan_runs
                WHERE assessment_id = ?
                FOR UPDATE
            `,
            [id]
        );

        scans = scanRows;

        const runningScans = scans.filter(
            (scan) =>
                String(scan.status).toLowerCase() === "running"
        );

        if (runningScans.length) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(409).json({
                error:
                    "Cannot delete an assessment while a scan is running.",
                running_scans: runningScans.map(
                    (scan) => scan.scan_number
                )
            });
        }

        counts.deleted_scans = scans.length;

        const [findingRows] = await connection.query(
            `
                SELECT id
                FROM findings
                WHERE assessment_id = ?
                FOR UPDATE
            `,
            [id]
        );

        counts.deleted_findings = findingRows.length;

        const [occurrenceRows] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ?
            `,
            [id]
        );

        counts.deleted_occurrences =
            countRow(occurrenceRows);

        const [retestRows] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM retests r
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ?
            `,
            [id]
        );

        counts.deleted_retests = countRow(retestRows);

        const [requestRows] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM http_requests
                WHERE assessment_id = ?
            `,
            [id]
        );

        counts.deleted_http_requests = countRow(requestRows);

        const [storedEvidence] = await connection.query(
            `
                SELECT DISTINCT e.id, e.file_path
                FROM evidence e
                LEFT JOIN findings f ON f.id = e.finding_id
                LEFT JOIN scan_runs sr ON sr.id = e.scan_id
                WHERE f.assessment_id = ?
                   OR sr.assessment_id = ?
            `,
            [id, id]
        );

        evidenceRows = storedEvidence;
        counts.deleted_evidence_records = evidenceRows.length;

        // Remove evidence records first because evidence.scan_id may not
        // have a database foreign-key cascade.
        await connection.execute(
            `
                DELETE e
                FROM evidence e
                LEFT JOIN findings f ON f.id = e.finding_id
                LEFT JOIN scan_runs sr ON sr.id = e.scan_id
                WHERE f.assessment_id = ?
                   OR sr.assessment_id = ?
            `,
            [id, id]
        );

        await connection.execute(
            `
                DELETE r
                FROM retests r
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ?
            `,
            [id]
        );

        await connection.execute(
            `
                DELETE o
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ?
            `,
            [id]
        );

        await connection.execute(
            "DELETE FROM findings WHERE assessment_id = ?",
            [id]
        );

        await connection.execute(
            "DELETE FROM http_requests WHERE assessment_id = ?",
            [id]
        );

        await connection.execute(
            "DELETE FROM scan_runs WHERE assessment_id = ?",
            [id]
        );

        await connection.execute(
            "DELETE FROM assessments WHERE id = ?",
            [id]
        );

        await connection.commit();
        transactionStarted = false;
    } catch (error) {
        if (connection && transactionStarted) {
            try {
                await connection.rollback();
            } catch {
                // Preserve the original error.
            }
        }

        console.error("Error deleting assessment:", error);

        return res.status(500).json({
            error: "Unable to delete assessment",
            message: error.message
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }

    // The database transaction has committed. Now clean associated files.
    const cleanup = await cleanupAssessmentFiles(
        scans.map((scan) => Number(scan.id)),
        evidenceRows
    );

    return res.json({
        message: cleanup.file_cleanup_warnings.length
            ? "Assessment deleted, but some files could not be cleaned up."
            : "Assessment and associated records deleted successfully.",

        assessment_id: id,
        assessment_title: title,

        ...counts,
        ...cleanup
    });
});

module.exports = router;