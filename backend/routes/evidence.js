const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const db = require("../config/db");

const router = express.Router();

const storage = multer.diskStorage({

    destination: (req, file, cb) => {
        cb(null, "uploads/");
    },

    filename: (req, file, cb) => {

        const extension =
            path.extname(file.originalname)
                .toLowerCase();

        const name =
            crypto.randomBytes(16)
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

        const ext =
            path.extname(file.originalname)
                .toLowerCase();

        if (allowed.includes(ext)) {
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

router.post(
    "/:findingId",
    upload.single("evidence"),
    async (req, res) => {

        try {

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
                    `INSERT INTO evidence
                    (
                        finding_id,
                        evidence_type,
                        file_path,
                        description
                    )
                    VALUES (?, ?, ?, ?)`,
                    [
                        Number(req.params.findingId),
                        evidence_type,
                        req.file.filename,
                        description || null
                    ]
                );

            res.status(201).json({
                message:
                    "Evidence uploaded",
                id: result.insertId
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error:
                    "Evidence upload failed"
            });
        }
    }
);

module.exports = router;