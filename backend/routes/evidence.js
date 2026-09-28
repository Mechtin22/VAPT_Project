const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");

const db = require("../config/db");

const router = express.Router();

const uploadDirectory = path.join(
    __dirname,
    "..",
    "uploads"
);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDirectory);
    },

    filename: (req, file, cb) => {
        const extension = path
            .extname(file.originalname)
            .toLowerCase();

        const name = crypto
            .randomBytes(16)
            .toString("hex");

        cb(
            null,
            `${name}${extension}`
        );
    }
});

const upload = multer({
    storage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        const allowed = [
            ".png",
            ".jpg",
            ".jpeg",
            ".pdf",
            ".txt"
        ];

        const extension = path
            .extname(file.originalname)
            .toLowerCase();

        if (allowed.includes(extension)) {
            cb(null, true);
        } else {
            cb(
                new Error(
                    "Unsupported file type"
                )
            );
        }
    }
});

router.get("/:findingId", async (req, res) => {
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

        const [rows] = await db.query(
            `
            SELECT *
            FROM evidence
            WHERE finding_id = ?
            ORDER BY created_at DESC
            `,
            [findingId]
        );

        res.json(rows);
    } catch (error) {
        console.error(
            "Error fetching evidence:",
            error
        );

        res.status(500).json({
            error: "Unable to retrieve evidence"
        });
    }
});

router.post(
    "/:findingId",
    upload.single("evidence"),
    async (req, res) => {
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

            if (!req.file) {
                return res.status(400).json({
                    error: "Evidence file required"
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
                !allowedTypes.includes(
                    evidence_type
                )
            ) {
                return res.status(400).json({
                    error: "Invalid evidence type"
                });
            }

            const [result] =
                await db.execute(
                    `
                    INSERT INTO evidence
                    (
                        finding_id,
                        evidence_type,
                        file_path,
                        description
                    )
                    VALUES (?, ?, ?, ?)
                    `,
                    [
                        findingId,
                        evidence_type,
                        req.file.filename,
                        description?.trim() || null
                    ]
                );

            res.status(201).json({
                message:
                    "Evidence uploaded successfully",
                id: result.insertId
            });
        } catch (error) {
            console.error(
                "Evidence upload error:",
                error
            );

            res.status(500).json({
                error:
                    "Evidence upload failed",
                message: error.message
            });
        }
    }
);

module.exports = router;