const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const assessmentRoutes = require("./routes/assessments");
const findingRoutes = require("./routes/findings");
const retestRoutes = require("./routes/retests");
const evidenceRoutes = require("./routes/evidence");
const reportRoutes = require("./routes/reports");

const app = express();

const PORT = process.env.PORT || 5000;

const uploadsDirectory = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadsDirectory)) {
    fs.mkdirSync(uploadsDirectory, {
        recursive: true
    });
}

app.use(
    cors({
        origin: "http://localhost:5173"
    })
);

app.use(express.json());

app.use(
    "/uploads",
    express.static(uploadsDirectory)
);

app.get("/api/health", (req, res) => {
    res.json({
        status: "OK",
        message: "VAPT Dashboard API running"
    });
});

app.use(
    "/api/assessments",
    assessmentRoutes
);

app.use(
    "/api/findings",
    findingRoutes
);

app.use(
    "/api/retests",
    retestRoutes
);

app.use(
    "/api/evidence",
    evidenceRoutes
);

app.use(
    "/api/reports",
    reportRoutes
);

app.use((err, req, res, next) => {
    console.error(err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        error: "Internal server error",
        message: err.message
    });
});

app.listen(
    PORT,
    "127.0.0.1",
    () => {
        console.log(
            `VAPT Backend running at http://localhost:${PORT}`
        );
    }
);