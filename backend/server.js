// const express = require("express");
// const cors = require("cors");
// const path = require("path");
// require("dotenv").config();

// const assessmentRoutes =
//     require("./routes/assessments");

// const findingRoutes =
//     require("./routes/findings");

// const app = express();

// app.use(
//     cors({
//         origin: "http://localhost:5173"
//     })
// );

// app.use(express.json());

// app.use(
//     "/uploads",
//     express.static(
//         path.join(__dirname, "uploads")
//     )
// );

// app.get("/api/health", (req, res) => {
//     res.json({
//         status: "OK",
//         message: "VAPT Dashboard API running"
//     });
// });

// app.use(
//     "/api/assessments",
//     assessmentRoutes
// );

// app.use(
//     "/api/findings",
//     findingRoutes
// );

// const PORT = process.env.PORT || 5000;

// app.listen(
//     PORT,
//     "127.0.0.1",
//     () => {
//         console.log(
//             `Server running on http://127.0.0.1:${PORT}`
//         );
//     }
// );











const express = require("express");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const assessmentRoutes = require("./routes/assessments");
const findingRoutes = require("./routes/findings");
const retestRoutes = require("./routes/retests");
const evidenceRoutes = require("./routes/evidence");
const reportRoutes = require("./routes/reports");

const app = express();

app.use(
    cors({
        origin: "http://localhost:5173"
    })
);

app.use(express.json());

app.use(
    "/uploads",
    express.static(path.join(__dirname, "uploads"))
);

app.get("/api/health", (req, res) => {
    res.json({
        status: "OK",
        message: "VAPT Dashboard API running"
    });
});

app.use("/api/assessments", assessmentRoutes);
app.use("/api/findings", findingRoutes);
app.use("/api/retests", retestRoutes);
app.use("/api/evidence", evidenceRoutes);
app.use("/api/reports", reportRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, "127.0.0.1", () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
});