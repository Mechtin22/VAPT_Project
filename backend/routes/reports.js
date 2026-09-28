const express = require("express");

const generateReport =
    require(
        "../services/reportGenerator"
    );

const router = express.Router();

router.get(
    "/:assessmentId",
    async (req, res) => {

        const id =
            Number(req.params.assessmentId);

        if (
            !Number.isInteger(id) ||
            id < 1
        ) {
            return res.status(400).json({
                error:
                    "Invalid assessment ID"
            });
        }

        try {

            await generateReport(
                id,
                res
            );

        } catch (error) {

            console.error(error);

            if (!res.headersSent) {

                res.status(500).json({
                    error:
                        "Report generation failed"
                });

            } else {

                res.destroy(error);
            }
        }
    }
);

module.exports = router;