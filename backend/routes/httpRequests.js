const express = require("express");

const db = require("../config/db");

const router = express.Router();


// =========================================================
// GET ALL HTTP REQUESTS
// =========================================================

router.get(
    "/",
    async (req, res) => {

        try {

            const [rows] = await db.query(
                `
                SELECT
                    h.id,
                    h.assessment_id,
                    h.method,
                    h.url,
                    h.host,
                    h.headers,
                    h.body,
                    h.raw_request,
                    h.created_at,
                    a.title AS assessment_title
                FROM http_requests h

                LEFT JOIN assessments a
                    ON h.assessment_id = a.id

                ORDER BY h.created_at DESC
                `
            );

            res.json(rows);

        } catch (error) {

            console.error(
                "GET HTTP requests error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load HTTP requests",
                message:
                    error.message
            });

        }

    }
);


// =========================================================
// GET SINGLE HTTP REQUEST
// =========================================================

router.get(
    "/:id",
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            if (
                !Number.isInteger(id) ||
                id < 1
            ) {

                return res.status(400).json({
                    error:
                        "Invalid HTTP request ID"
                });

            }

            const [rows] =
                await db.query(
                    `
                    SELECT
                        h.*,
                        a.title AS assessment_title
                    FROM http_requests h

                    LEFT JOIN assessments a
                        ON h.assessment_id = a.id

                    WHERE h.id = ?
                    `,
                    [id]
                );

            if (rows.length === 0) {

                return res.status(404).json({
                    error:
                        "HTTP request not found"
                });

            }

            res.json(rows[0]);

        } catch (error) {

            console.error(
                "GET HTTP request error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load HTTP request",
                message:
                    error.message
            });

        }

    }
);


// =========================================================
// CREATE HTTP REQUEST
// =========================================================

router.post(
    "/",
    async (req, res) => {

        try {

            const {
                assessment_id,
                method,
                url,
                host,
                headers,
                body,
                raw_request
            } = req.body;


            // ---------------------------------------------
            // BASIC VALIDATION
            // ---------------------------------------------

            if (
                !method ||
                !raw_request
            ) {

                return res.status(400).json({
                    error:
                        "Method and raw_request are required"
                });

            }


            const cleanMethod =
                String(method)
                    .trim()
                    .toUpperCase();

            const allowedMethods = [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS"
            ];

            if (
                !allowedMethods.includes(
                    cleanMethod
                )
            ) {

                return res.status(400).json({
                    error:
                        "Invalid HTTP method"
                });

            }


            // ---------------------------------------------
            // VALIDATE ASSESSMENT IF PROVIDED
            // ---------------------------------------------

            let assessmentId = null;

            if (
                assessment_id !== undefined &&
                assessment_id !== null &&
                assessment_id !== ""
            ) {

                assessmentId =
                    Number(assessment_id);

                if (
                    !Number.isInteger(
                        assessmentId
                    ) ||
                    assessmentId < 1
                ) {

                    return res.status(400).json({
                        error:
                            "Invalid assessment ID"
                    });

                }


                const [assessment] =
                    await db.query(
                        `
                        SELECT id
                        FROM assessments
                        WHERE id = ?
                        `,
                        [assessmentId]
                    );

                if (
                    assessment.length === 0
                ) {

                    return res.status(400).json({
                        error:
                            "Assessment does not exist"
                    });

                }

            }


            // ---------------------------------------------
            // SAVE
            // ---------------------------------------------

            const [result] =
                await db.execute(
                    `
                    INSERT INTO http_requests
                    (
                        assessment_id,
                        method,
                        url,
                        host,
                        headers,
                        body,
                        raw_request
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    `,
                    [
                        assessmentId,
                        cleanMethod,
                        url?.trim() || null,
                        host?.trim() || null,
                        headers || null,
                        body || null,
                        String(raw_request)
                    ]
                );


            res.status(201).json({
                message:
                    "HTTP request saved successfully",
                id:
                    result.insertId
            });

        } catch (error) {

            console.error(
                "POST HTTP request error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to save HTTP request",
                message:
                    error.message
            });

        }

    }
);


// =========================================================
// DELETE HTTP REQUEST
// =========================================================

router.delete(
    "/:id",
    async (req, res) => {

        try {

            const id =
                Number(req.params.id);

            if (
                !Number.isInteger(id) ||
                id < 1
            ) {

                return res.status(400).json({
                    error:
                        "Invalid HTTP request ID"
                });

            }

            const [result] =
                await db.execute(
                    `
                    DELETE FROM http_requests
                    WHERE id = ?
                    `,
                    [id]
                );

            if (
                result.affectedRows === 0
            ) {

                return res.status(404).json({
                    error:
                        "HTTP request not found"
                });

            }

            res.json({
                message:
                    "HTTP request deleted successfully"
            });

        } catch (error) {

            console.error(
                "DELETE HTTP request error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to delete HTTP request",
                message:
                    error.message
            });

        }

    }
);


module.exports = router;