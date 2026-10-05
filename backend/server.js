const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

require("dotenv").config();

const assessmentRoutes = require("./routes/assessments");
const findingRoutes = require("./routes/findings");
const evidenceRoutes = require("./routes/evidence");
const retestRoutes = require("./routes/retests");
const reportRoutes = require("./routes/reports");
const httpRequestRoutes = require("./routes/httpRequests");
const scanRoutes = require("./routes/scans");

const app = express();

const PORT = Number(process.env.PORT || 5000);


// =========================================================
// UPLOAD DIRECTORY
// =========================================================

const uploadsDirectory = path.join(
    __dirname,
    "uploads"
);

if (!fs.existsSync(uploadsDirectory)) {
    fs.mkdirSync(uploadsDirectory, {
        recursive: true
    });
}


// =========================================================
// CORS
// =========================================================

const allowedOrigins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173"
];

app.use(
    cors({
        origin: (origin, callback) => {

            // Allow requests such as Postman/curl
            // where Origin may not exist.
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(
                new Error("CORS origin not allowed")
            );
        }
    })
);


// =========================================================
// BODY PARSING
// =========================================================

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "2mb"
    })
);


// =========================================================
// STATIC UPLOADS
// =========================================================

app.use(
    "/uploads",
    express.static(uploadsDirectory)
);


// =========================================================
// HEALTH CHECK
// =========================================================

app.get(
    "/api/health",
    (req, res) => {

        res.json({
            status: "OK",
            message: "VAPT Dashboard API running",
            timestamp: new Date().toISOString()
        });

    }
);


// =========================================================
// API ROUTES
// =========================================================

app.use(
    "/api/assessments",
    assessmentRoutes
);

app.use(
    "/api/findings",
    findingRoutes
);

app.use(
    "/api/evidence",
    evidenceRoutes
);

app.use(
    "/api/retests",
    retestRoutes
);

app.use(
    "/api/reports",
    reportRoutes
);

app.use(
    "/api/requests",
    httpRequestRoutes
);

app.use(
    "/api/scans",
    scanRoutes
);

// =========================================================
// 404 HANDLER
// =========================================================

app.use(
    (req, res) => {

        res.status(404).json({
            error: "API endpoint not found",
            path: req.originalUrl
        });

    }
);


// =========================================================
// GLOBAL ERROR HANDLER
// =========================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "Server error:",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        res.status(500).json({
            error: "Internal server error",
            message: err.message
        });

    }
);


// =========================================================
// START SERVER
// =========================================================

app.listen(
    PORT,
    "127.0.0.1",
    () => {

        console.log(
            `VAPT Backend running at http://localhost:${PORT}`
        );

    }
);