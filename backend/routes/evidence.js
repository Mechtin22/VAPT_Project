const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const db = require("../config/db");

const router = express.Router();

const uploadDirectory = path.join(
    __dirname,
    "..",
    "uploads"
);

// =========================================================
// UPLOAD CONFIGURATION
// =========================================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        fs.mkdir(
            uploadDirectory,
            { recursive: true },
            (error) => cb(error, uploadDirectory)
        );
    },

    filename: (req, file, cb) => {
        const extension = path
            .extname(file.originalname)
            .toLowerCase();

        cb(
            null,
            `${crypto.randomBytes(16).toString("hex")}${extension}`
        );
    }
});

const upload = multer({
    storage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        const allowedExtensions = [
            ".png",
            ".jpg",
            ".jpeg",
            ".pdf",
            ".txt"
        ];

        const extension = path
            .extname(file.originalname)
            .toLowerCase();

        if (allowedExtensions.includes(extension)) {
            cb(null, true);
        } else {
            cb(new Error("Unsupported file type"));
        }
    }
});


// =========================================================
// GET EVIDENCE FOR A PARTICULAR SCAN
// GET /api/evidence/scan/:scanId
//
// IMPORTANT: Keep this route before /:findingId.
// =========================================================

router.get(
    "/scan/:scanId",
    async (req, res) => {
        const scanId = Number(req.params.scanId);

        if (
            !Number.isInteger(scanId) ||
            scanId < 1
        ) {
            return res.status(400).json({
                error: "Invalid scan ID"
            });
        }

        try {
            const [scanRows] = await db.query(
                `
                    SELECT id, assessment_id, scan_number
                    FROM scan_runs
                    WHERE id = ?
                `,
                [scanId]
            );

            if (!scanRows.length) {
                return res.status(404).json({
                    error: "Scan not found"
                });
            }

            const [rows] = await db.query(
                `
                    SELECT
                        e.id,
                        e.finding_id,

                        COALESCE(
                            e.scan_id,
                            f.scan_id
                        ) AS scan_id,

                        e.occurrence_id,
                        e.evidence_type,
                        e.file_path,
                        e.description,
                        e.created_at,

                        f.vulnerability,
                        f.severity,
                        f.status,

                        o.detected_vulnerability,
                        o.affected_module,
                        o.parameter_name

                    FROM evidence e

                    LEFT JOIN findings f
                        ON f.id = e.finding_id

                    LEFT JOIN finding_occurrences o
                        ON o.id = e.occurrence_id

                    WHERE COALESCE(
                        e.scan_id,
                        f.scan_id
                    ) = ?

                    ORDER BY
                        e.created_at DESC,
                        e.id DESC
                `,
                [scanId]
            );

            return res.json({
                scan: scanRows[0],
                evidence: rows
            });
        } catch (error) {
            console.error(
                "Error fetching scan evidence:",
                error
            );

            return res.status(500).json({
                error: "Failed to load scan evidence",
                message: error.message
            });
        }
    }
);


// =========================================================
// GET EVIDENCE FOR ONE FINDING
// GET /api/evidence/:findingId
// =========================================================

router.get(
    "/:findingId",
    async (req, res) => {
        const findingId =
            Number(req.params.findingId);

        if (
            !Number.isInteger(findingId) ||
            findingId < 1
        ) {
            return res.status(400).json({
                error: "Invalid finding ID"
            });
        }

        try {
            const [rows] = await db.query(
                `
                    SELECT
                        e.*,
                        f.vulnerability,
                        f.severity
                    FROM evidence e

                    LEFT JOIN findings f
                        ON f.id = e.finding_id

                    WHERE e.finding_id = ?

                    ORDER BY e.created_at DESC
                `,
                [findingId]
            );

            return res.json(rows);
        } catch (error) {
            console.error(
                "Error fetching finding evidence:",
                error
            );

            return res.status(500).json({
                error: "Unable to retrieve evidence",
                message: error.message
            });
        }
    }
);


// =========================================================
// UPLOAD MANUAL EVIDENCE
// POST /api/evidence/:findingId
//
// New uploads inherit the scan ID of their parent finding.
// =========================================================

router.post(
    "/:findingId",
    upload.single("evidence"),
    async (req, res) => {
        let uploadedFilePath = null;

        try {
            const findingId =
                Number(req.params.findingId);

            if (
                !Number.isInteger(findingId) ||
                findingId < 1
            ) {
                return res.status(400).json({
                    error: "Invalid finding ID"
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    error: "Evidence file required"
                });
            }

            uploadedFilePath = req.file.path;

            const [findingRows] =
                await db.query(
                    `
                        SELECT id, scan_id
                        FROM findings
                        WHERE id = ?
                    `,
                    [findingId]
                );

            if (!findingRows.length) {
                await fs.promises.unlink(
                    uploadedFilePath
                ).catch(() => {});

                return res.status(404).json({
                    error: "Finding not found"
                });
            }

            const {
                evidence_type,
                description
            } = req.body;

            const allowedTypes = [
                "Screenshot",
                "HTTP Request",
                "HTTP Response",
                "Scan Result",
                "Other"
            ];

            if (
                !allowedTypes.includes(evidence_type)
            ) {
                await fs.promises.unlink(
                    uploadedFilePath
                ).catch(() => {});

                return res.status(400).json({
                    error: "Invalid evidence type"
                });
            }

            const scanId =
                findingRows[0].scan_id || null;

            const relativePath = path
                .relative(
                    uploadDirectory,
                    uploadedFilePath
                )
                .split(path.sep)
                .join("/");

            const [result] = await db.execute(
                `
                    INSERT INTO evidence
                    (
                        finding_id,
                        scan_id,
                        occurrence_id,
                        evidence_type,
                        file_path,
                        description
                    )
                    VALUES (?, ?, NULL, ?, ?, ?)
                `,
                [
                    findingId,
                    scanId,
                    evidence_type,
                    relativePath,
                    description?.trim() || null
                ]
            );

            return res.status(201).json({
                message:
                    "Evidence uploaded successfully",

                id:
                    result.insertId,

                finding_id:
                    findingId,

                scan_id:
                    scanId
            });
        } catch (error) {
            if (uploadedFilePath) {
                await fs.promises.unlink(
                    uploadedFilePath
                ).catch(() => {});
            }

            console.error(
                "Evidence upload error:",
                error
            );

            return res.status(500).json({
                error: "Evidence upload failed",
                message: error.message
            });
        }
    }
);


module.exports = router;