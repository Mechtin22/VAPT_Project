const express = require("express");
const { URL } = require("url");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const db = require("../config/db");
const { scanTarget } = require("../services/scanner");

const router = express.Router();

const uploadsRoot = path.resolve(__dirname, "..", "uploads");

const automaticEvidenceRoot = path.resolve(
    uploadsRoot,
    "automatic-evidence"
);

const SECURITY_LEVELS = [
    "low",
    "medium",
    "high",
    "impossible"
];

const severityRank = {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Info: 1
};


// =========================================================
// VALIDATE LOCAL DVWA TARGET
// =========================================================

function isLocalDvwaTarget(value) {
    try {
        const url = new URL(value);

        return (
            ["http:", "https:"].includes(url.protocol) &&
            ["localhost", "127.0.0.1"].includes(
                url.hostname.toLowerCase()
            ) &&
            /^\/dvwa\/?$/i.test(url.pathname) &&
            !url.username &&
            !url.password &&
            !url.search &&
            !url.hash
        );
    } catch {
        return false;
    }
}


// =========================================================
// FINDING HELPERS
// =========================================================

function getCategory(vulnerability) {
    if (!vulnerability) {
        return "Unknown";
    }

    if (/^Missing .* header$/i.test(vulnerability)) {
        return "Missing Security Headers";
    }

    return vulnerability;
}

function extractParameter(affectedModule) {
    if (typeof affectedModule !== "string") {
        return null;
    }

    const match = affectedModule.match(
        /\[([^\]]+)\]\s*$/
    );

    return match ? match[1] : null;
}

function highestSeverity(findings) {
    return findings.reduce(
        (highest, finding) => {
            const current =
                severityRank[finding.severity] || 0;

            const existing =
                severityRank[highest] || 0;

            return current > existing
                ? finding.severity
                : highest;
        },
        "Info"
    );
}

function groupFindings(findings) {
    const groups = new Map();

    for (const finding of findings) {
        const category = getCategory(
            finding.vulnerability
        );

        if (!groups.has(category)) {
            groups.set(category, []);
        }

        groups.get(category).push(finding);
    }

    return Array.from(groups.entries()).map(
        ([category, items]) => ({
            category,
            items,
            severity: highestSeverity(items)
        })
    );
}

function uniqueText(items, field) {
    return Array.from(
        new Set(
            items
                .map((item) => item[field])
                .filter(Boolean)
        )
    ).join("\n");
}

function buildDescription(group) {
    if (group.category === "Missing Security Headers") {
        return (
            "One or more recommended HTTP security headers " +
            "are missing from scanned DVWA pages. Individual " +
            "observations are recorded as occurrences."
        );
    }

    return uniqueText(group.items, "description");
}

function buildAffectedModule(group) {
    return `${group.items.length} affected location(s)`;
}


// =========================================================
// EVIDENCE FILE PATH SAFETY
// =========================================================

function resolveStoredUploadPath(storedPath) {
    if (
        !storedPath ||
        typeof storedPath !== "string"
    ) {
        return null;
    }

    let value = storedPath
        .trim()
        .replace(/\\/g, "/");

    if (!value) {
        return null;
    }

    if (/^https?:\/\//i.test(value)) {
        try {
            const parsed = new URL(value);
            const marker = "/uploads/";
            const index = parsed.pathname.indexOf(marker);

            if (index < 0) {
                return null;
            }

            value = decodeURIComponent(
                parsed.pathname.slice(
                    index + marker.length
                )
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

    const relative = path.relative(
        uploadsRoot,
        resolved
    );

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
    const relative = path.relative(
        automaticEvidenceRoot,
        filePath
    );

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
        if (error.code === "ENOENT") {
            return 0;
        }

        throw error;
    }

    let count = 0;

    for (const entry of entries) {
        const entryPath = path.join(
            directory,
            entry.name
        );

        if (entry.isDirectory()) {
            count += await countFilesRecursively(entryPath);
        } else if (entry.isFile()) {
            count += 1;
        }
    }

    return count;
}


// =========================================================
// CLEAN UP FILES FOR DELETED SCANS
// =========================================================

async function cleanupEvidenceFiles(scanIds, evidenceRows) {
    const warnings = [];

    let deletedAutomaticFiles = 0;
    let deletedManualFiles = 0;

    for (const scanId of scanIds) {
        const scanDirectory = path.resolve(
            automaticEvidenceRoot,
            `scan-${Number(scanId)}`
        );

        if (
            path.dirname(scanDirectory) !==
            automaticEvidenceRoot
        ) {
            warnings.push({
                scan_id: scanId,
                message: "Unexpected evidence directory path."
            });

            continue;
        }

        try {
            deletedAutomaticFiles +=
                await countFilesRecursively(scanDirectory);

            await fs.rm(scanDirectory, {
                recursive: true,
                force: true
            });
        } catch (error) {
            warnings.push({
                scan_id: scanId,
                message: error.message
            });
        }
    }

    const manualFiles = new Map();

    for (const evidence of evidenceRows) {
        const absolutePath = resolveStoredUploadPath(
            evidence.file_path
        );

        if (!absolutePath) {
            if (evidence.file_path) {
                warnings.push({
                    evidence_id: evidence.id,
                    message:
                        "Unsafe evidence path; file was not deleted."
                });
            }

            continue;
        }

        if (isInsideAutomaticEvidence(absolutePath)) {
            continue;
        }

        manualFiles.set(
            `${evidence.file_path}|${absolutePath}`,
            {
                storedPath: evidence.file_path,
                absolutePath
            }
        );
    }

    for (const file of manualFiles.values()) {
        try {
            // Keep any file that is still referenced by another
            // evidence record.
            const [references] = await db.query(
                `
                    SELECT COUNT(*) AS total
                    FROM evidence
                    WHERE file_path = ?
                `,
                [file.storedPath]
            );

            if (Number(references[0]?.total || 0) > 0) {
                continue;
            }

            await fs.unlink(file.absolutePath);
            deletedManualFiles += 1;
        } catch (error) {
            if (error.code !== "ENOENT") {
                warnings.push({
                    file_path: file.storedPath,
                    message: error.message
                });
            }
        }
    }

    return {
        deleted_automatic_evidence_files:
            deletedAutomaticFiles,

        deleted_manual_evidence_files:
            deletedManualFiles,

        file_cleanup_warnings: warnings
    };
}


// =========================================================
// CREATE SCAN RUN
// =========================================================

async function createScanRun(
    assessmentId,
    securityLevel
) {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        // Lock the assessment row to reduce conflicts if two scans
        // are started for the same assessment simultaneously.
        const [assessmentRows] = await connection.query(
            `
                SELECT id
                FROM assessments
                WHERE id = ?
                FOR UPDATE
            `,
            [assessmentId]
        );

        if (!assessmentRows.length) {
            throw new Error("Assessment not found.");
        }

        const [rows] = await connection.query(
            `
                SELECT
                    COALESCE(MAX(scan_number), 0) + 1 AS next_scan
                FROM scan_runs
                WHERE assessment_id = ?
            `,
            [assessmentId]
        );

        const scanNumber = Number(
            rows[0].next_scan
        );

        const [result] = await connection.execute(
            `
                INSERT INTO scan_runs
                (
                    assessment_id,
                    scan_number,
                    status,
                    security_level
                )
                VALUES (?, ?, 'Running', ?)
            `,
            [
                assessmentId,
                scanNumber,
                securityLevel
            ]
        );

        await connection.commit();

        return {
            scanId: result.insertId,
            scanNumber
        };
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
}


// =========================================================
// COMPLETE OR FAIL A SCAN
// =========================================================

async function completeScan(scanId, summary) {
    await db.execute(
        `
            UPDATE scan_runs
            SET
                status = 'Completed',
                completed_at = CURRENT_TIMESTAMP,
                pages_scanned = ?,
                findings_detected = ?,
                findings_created = ?,
                duration_ms = ?
            WHERE id = ?
        `,
        [
            Number(summary.pages_scanned || 0),
            Number(summary.findings_detected || 0),
            Number(summary.findings_created || 0),
            Number(summary.duration_ms || 0),
            scanId
        ]
    );
}

async function failScan(scanId) {
    try {
        await db.execute(
            `
                UPDATE scan_runs
                SET
                    status = 'Failed',
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [scanId]
        );
    } catch (error) {
        console.error(
            "Could not update failed scan status:",
            error.message
        );
    }
}


// =========================================================
// CREATE A FINDING CATEGORY
// =========================================================

async function createCategoryFinding(
    assessmentId,
    scanId,
    group
) {
    const description = buildDescription(group);
    const observedResult = uniqueText(
        group.items,
        "observed_result"
    );
    const impact = uniqueText(
        group.items,
        "impact"
    );
    const affectedModule = buildAffectedModule(group);

    const [insertResult] = await db.execute(
        `
            INSERT INTO findings
            (
                assessment_id,
                scan_id,
                vulnerability,
                affected_module,
                description,
                observed_result,
                impact,
                severity,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
            assessmentId,
            scanId,
            group.category,
            affectedModule,
            description,
            observedResult,
            impact,
            group.severity,
            "Open"
        ]
    );

    return {
        findingId: insertResult.insertId,
        affectedModule,
        description,
        observedResult,
        impact
    };
}


// =========================================================
// CREATE OCCURRENCES AND AUTOMATIC EVIDENCE
// Every occurrence gets a JSON evidence file and an evidence
// database row. Failed evidence writes are logged explicitly.
// =========================================================

async function createOccurrencesAndEvidence({
    findingId,
    scanId,
    scanNumber,
    targetUrl,
    category,
    severity,
    items
}) {
    let evidenceCreated = 0;
    let evidenceFailed = 0;

    for (const item of items) {
        const [occurrenceResult] = await db.execute(
            `
                INSERT INTO finding_occurrences
                (
                    finding_id,
                    detected_vulnerability,
                    affected_module,
                    parameter_name
                )
                VALUES (?, ?, ?, ?)
            `,
            [
                findingId,
                item.vulnerability || category,
                item.affected_module || null,
                extractParameter(item.affected_module)
            ]
        );

        const occurrenceId = occurrenceResult.insertId;

        const evidenceRecord = {
            evidence_type: "Automated Scan Result",
            evidence_source: "VAPT DVWA scanner",
            created_at: new Date().toISOString(),

            target_url: targetUrl,
            scan_id: scanId,
            scan_number: scanNumber,

            finding_id: findingId,
            occurrence_id: occurrenceId,

            category,
            detected_vulnerability:
                item.vulnerability || category,

            severity: item.severity || severity,
            affected_module: item.affected_module || null,
            parameter_name:
                extractParameter(item.affected_module),

            description: item.description || null,
            observed_result: item.observed_result || null,
            impact: item.impact || null,

            validation_note:
                "Automated observation summary. Validate findings manually before treating them as confirmed vulnerabilities. This evidence record intentionally excludes session cookies, passwords, and complete raw HTTP responses."
        };

        const relativeDirectory = path.join(
            "automatic-evidence",
            `scan-${scanId}`
        );

        const absoluteDirectory = path.join(
            uploadsRoot,
            relativeDirectory
        );

        const fileName =
            `finding-${findingId}-occurrence-${occurrenceId}-${crypto.randomUUID()}.json`;

        const absoluteFilePath = path.join(
            absoluteDirectory,
            fileName
        );

        const storedFilePath = path
            .join(relativeDirectory, fileName)
            .split(path.sep)
            .join("/");

        let fileWritten = false;

        try {
            await fs.mkdir(absoluteDirectory, {
                recursive: true
            });

            await fs.writeFile(
                absoluteFilePath,
                JSON.stringify(evidenceRecord, null, 2),
                "utf8"
            );

            fileWritten = true;

            await db.execute(
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
                    VALUES (?, ?, ?, ?, ?, ?)
                `,
                [
                    findingId,
                    scanId,
                    occurrenceId,
                    "Scan Result",
                    storedFilePath,
                    `Automatic evidence for ${item.vulnerability || category} in scan #${scanNumber}.`
                ]
            );

            evidenceCreated += 1;
        } catch (error) {
            evidenceFailed += 1;

            if (fileWritten) {
                try {
                    await fs.unlink(absoluteFilePath);
                } catch {
                    // Keep the original error.
                }
            }

            console.error(
                `Evidence creation failed for scan ${scanId}, ` +
                `occurrence ${occurrenceId}:`,
                error.message
            );
        }
    }

    return {
        evidenceCreated,
        evidenceFailed
    };
}


// =========================================================
// START A SCAN
// POST /api/scans/:assessmentId
// =========================================================

router.post("/:assessmentId", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);

    if (
        !Number.isInteger(assessmentId) ||
        assessmentId < 1
    ) {
        return res.status(400).json({
            error: "Invalid assessment ID."
        });
    }

    const requestedSecurityLevel = String(
        req.body?.security_level ??
        process.env.DVWA_SECURITY_LEVEL ??
        "low"
    ).trim().toLowerCase();

    if (
        !SECURITY_LEVELS.includes(requestedSecurityLevel)
    ) {
        return res.status(400).json({
            error:
                "Invalid DVWA security level. Choose low, medium, high, or impossible."
        });
    }

    let scanId = null;

    try {
        const [rows] = await db.query(
            `
                SELECT id, title, target_url
                FROM assessments
                WHERE id = ?
            `,
            [assessmentId]
        );

        if (!rows.length) {
            return res.status(404).json({
                error: "Assessment not found."
            });
        }

        const assessment = rows[0];

        if (!isLocalDvwaTarget(assessment.target_url)) {
            return res.status(400).json({
                error:
                    "The scanner is restricted to the local DVWA root, " +
                    "for example http://localhost/DVWA/."
            });
        }

        const scan = await createScanRun(
            assessmentId,
            requestedSecurityLevel
        );

        scanId = scan.scanId;

        console.log(
            `Starting Assessment #${assessmentId} - Scan #${scan.scanNumber}`
        );
        console.log(`Target: ${assessment.target_url}`);
        console.log(
            `Requested DVWA security level: ${requestedSecurityLevel}`
        );

        const startedAt = Date.now();

        const result = await scanTarget(
            assessment.target_url,
            {
                securityLevel: requestedSecurityLevel
            }
        );

        const durationMs = Date.now() - startedAt;

        // Never report that a scan ran at the wrong level.
        if (
            String(result.security_level || "").toLowerCase() !==
            requestedSecurityLevel
        ) {
            throw new Error(
                `Security-level mismatch. Requested ${requestedSecurityLevel}, ` +
                `scanner returned ${result.security_level || "unknown"}.`
            );
        }

        if (
            result.authentication?.securityLevelVerified !== true
        ) {
            throw new Error(
                "DVWA security level was not verified. The scan cannot be marked as completed."
            );
        }

        const rawFindings = Array.isArray(result.findings)
            ? result.findings
            : [];

        const groups = groupFindings(rawFindings);

        const createdCategories = [];

        let findingsCreated = 0;
        let automaticEvidenceCreated = 0;
        let automaticEvidenceFailed = 0;

        for (const group of groups) {
            if (!group.items.length) {
                continue;
            }

            const finding = await createCategoryFinding(
                assessmentId,
                scanId,
                group
            );

            findingsCreated += 1;

            const evidenceResult =
                await createOccurrencesAndEvidence({
                    findingId: finding.findingId,
                    scanId,
                    scanNumber: scan.scanNumber,
                    targetUrl: assessment.target_url,
                    category: group.category,
                    severity: group.severity,
                    items: group.items
                });

            automaticEvidenceCreated +=
                evidenceResult.evidenceCreated;

            automaticEvidenceFailed +=
                evidenceResult.evidenceFailed;

            createdCategories.push({
                id: finding.findingId,
                vulnerability: group.category,
                severity: group.severity,
                status: "Open",
                affected_module: finding.affectedModule,
                occurrence_count: group.items.length,
                description: finding.description,
                observed_result: finding.observedResult,
                impact: finding.impact,
                occurrences: group.items.map((item) => ({
                    detected_vulnerability: item.vulnerability,
                    affected_module: item.affected_module,
                    parameter_name:
                        extractParameter(item.affected_module)
                }))
            });
        }

        const summary = {
            pages_scanned: Number(result.pages_scanned || 0),
            findings_detected: rawFindings.length,
            findings_created: findingsCreated,
            duration_ms: durationMs
        };

        await completeScan(scanId, summary);

        await db.execute(
            `
                UPDATE assessments
                SET status = 'Completed'
                WHERE id = ?
            `,
            [assessmentId]
        );

        console.log(
            `Scan #${scan.scanNumber} completed: ` +
            `${summary.pages_scanned} pages, ` +
            `${summary.findings_detected} observations, ` +
            `${findingsCreated} findings, ` +
            `${automaticEvidenceCreated} evidence records, ` +
            `${automaticEvidenceFailed} evidence failures.`
        );

        const hasEvidenceWarnings =
            automaticEvidenceFailed > 0;

        return res.json({
            message: hasEvidenceWarnings
                ? "Scan completed, but some evidence records could not be saved."
                : "Scan completed successfully.",

            assessment_id: assessmentId,
            scan_id: scanId,
            scan_number: scan.scanNumber,

            target_url: assessment.target_url,
            authenticated: result.authenticated ?? null,

            security_level: result.security_level,
            security_level_verified:
                result.authentication?.securityLevelVerified === true,

            pages_scanned: summary.pages_scanned,
            html_pages_scanned:
                Number(result.html_pages_scanned || 0),

            javascript_files_scanned:
                Number(result.javascript_files_scanned || 0),

            api_endpoints_discovered:
                Number(result.api_endpoints_discovered || 0),

            forms_discovered:
                Number(result.forms_discovered || 0),

            parameters_tested:
                Number(result.parameters_tested || 0),

            duration_ms: summary.duration_ms,

            findings_detected: summary.findings_detected,
            findings_created: summary.findings_created,

            automatic_evidence_created:
                automaticEvidenceCreated,

            automatic_evidence_failed:
                automaticEvidenceFailed,

            findings: createdCategories,
            categories: createdCategories
        });
    } catch (error) {
        console.error("Scan error:", error);

        if (scanId !== null) {
            await failScan(scanId);
        }

        return res.status(500).json({
            error: "Scan failed",
            message: error.message
        });
    }
});


// =========================================================
// GET SCAN HISTORY FOR AN ASSESSMENT
// GET /api/scans/:assessmentId
// =========================================================

router.get("/:assessmentId", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);

    if (
        !Number.isInteger(assessmentId) ||
        assessmentId < 1
    ) {
        return res.status(400).json({
            error: "Invalid assessment ID."
        });
    }

    try {
        const [scans] = await db.query(
            `
                SELECT
                    id,
                    assessment_id,
                    scan_number,
                    status,
                    security_level,
                    started_at,
                    completed_at,
                    pages_scanned,
                    findings_detected,
                    findings_created,
                    duration_ms
                FROM scan_runs
                WHERE assessment_id = ?
                ORDER BY scan_number DESC, id DESC
            `,
            [assessmentId]
        );

        const [rows] = await db.query(
            `
                SELECT
                    f.id,
                    f.scan_id,
                    f.vulnerability,
                    f.description,
                    f.observed_result,
                    f.impact,
                    f.severity,
                    f.status,
                    o.id AS occurrence_id,
                    o.detected_vulnerability,
                    o.affected_module,
                    o.parameter_name
                FROM findings f
                LEFT JOIN finding_occurrences o
                    ON o.finding_id = f.id
                WHERE f.assessment_id = ?
                ORDER BY f.id DESC, o.id ASC
            `,
            [assessmentId]
        );

        const scanMap = new Map();

        for (const scan of scans) {
            scanMap.set(
                Number(scan.id),
                {
                    ...scan,
                    findings: []
                }
            );
        }

        const findingMap = new Map();

        for (const row of rows) {
            if (row.scan_id == null) {
                continue;
            }

            const scanId = Number(row.scan_id);

            if (!scanMap.has(scanId)) {
                continue;
            }

            if (!findingMap.has(Number(row.id))) {
                const finding = {
                    id: row.id,
                    scan_id: row.scan_id,
                    vulnerability: row.vulnerability,
                    description: row.description,
                    observed_result: row.observed_result,
                    impact: row.impact,
                    severity: row.severity,
                    status: row.status,
                    occurrences: []
                };

                findingMap.set(
                    Number(row.id),
                    finding
                );

                scanMap.get(scanId).findings.push(finding);
            }

            if (row.occurrence_id != null) {
                findingMap
                    .get(Number(row.id))
                    .occurrences.push({
                        id: row.occurrence_id,
                        detected_vulnerability:
                            row.detected_vulnerability,
                        affected_module: row.affected_module,
                        parameter_name: row.parameter_name
                    });
            }
        }

        return res.json(
            Array.from(scanMap.values())
        );
    } catch (error) {
        console.error(
            "Error loading scan history:",
            error
        );

        return res.status(500).json({
            error: "Failed to load scan history.",
            message: error.message
        });
    }
});


// =========================================================
// CLEAR ALL SCAN HISTORY FOR ONE ASSESSMENT
// DELETE /api/scans/:assessmentId/history
// =========================================================

router.delete(
    "/:assessmentId/history",
    async (req, res) => {
        const assessmentId = Number(req.params.assessmentId);

        if (
            !Number.isInteger(assessmentId) ||
            assessmentId < 1
        ) {
            return res.status(400).json({
                error: "Invalid assessment ID."
            });
        }

        let connection;
        let transactionStarted = false;

        let scanIds = [];
        let evidenceRows = [];

        const counts = {
            deleted_scans: 0,
            deleted_findings: 0,
            deleted_occurrences: 0,
            deleted_retests: 0,
            deleted_evidence_records: 0
        };

        try {
            connection = await db.getConnection();

            await connection.beginTransaction();
            transactionStarted = true;

            const [assessmentRows] =
                await connection.query(
                    `
                        SELECT id
                        FROM assessments
                        WHERE id = ?
                        FOR UPDATE
                    `,
                    [assessmentId]
                );

            if (!assessmentRows.length) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(404).json({
                    error: "Assessment not found."
                });
            }

            const [scans] = await connection.query(
                `
                    SELECT id, status
                    FROM scan_runs
                    WHERE assessment_id = ?
                    FOR UPDATE
                `,
                [assessmentId]
            );

            const runningScan = scans.find(
                (scan) =>
                    String(scan.status).toLowerCase() === "running"
            );

            if (runningScan) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(409).json({
                    error:
                        "Cannot clear history while a scan is running."
                });
            }

            scanIds = scans.map(
                (scan) => Number(scan.id)
            );

            counts.deleted_scans = scans.length;

            const [findings] = await connection.query(
                `
                    SELECT id
                    FROM findings
                    WHERE assessment_id = ?
                    FOR UPDATE
                `,
                [assessmentId]
            );

            counts.deleted_findings = findings.length;

            const [occurrences] =
                await connection.query(
                    `
                        SELECT COUNT(*) AS total
                        FROM finding_occurrences o
                        INNER JOIN findings f
                            ON f.id = o.finding_id
                        WHERE f.assessment_id = ?
                    `,
                    [assessmentId]
                );

            counts.deleted_occurrences = Number(
                occurrences[0]?.total || 0
            );

            const [retests] = await connection.query(
                `
                    SELECT COUNT(*) AS total
                    FROM retests r
                    INNER JOIN findings f
                        ON f.id = r.finding_id
                    WHERE f.assessment_id = ?
                `,
                [assessmentId]
            );

            counts.deleted_retests = Number(
                retests[0]?.total || 0
            );

            const [storedEvidence] =
                await connection.query(
                    `
                        SELECT DISTINCT e.id, e.file_path
                        FROM evidence e
                        LEFT JOIN findings f
                            ON f.id = e.finding_id
                        WHERE e.scan_id IN (
                            SELECT id
                            FROM scan_runs
                            WHERE assessment_id = ?
                        )
                        OR f.assessment_id = ?
                    `,
                    [assessmentId, assessmentId]
                );

            evidenceRows = storedEvidence;

            counts.deleted_evidence_records =
                evidenceRows.length;

            await connection.execute(
                `
                    DELETE FROM evidence
                    WHERE scan_id IN (
                        SELECT id
                        FROM scan_runs
                        WHERE assessment_id = ?
                    )
                    OR finding_id IN (
                        SELECT id
                        FROM findings
                        WHERE assessment_id = ?
                    )
                `,
                [assessmentId, assessmentId]
            );

            await connection.execute(
                `
                    DELETE r
                    FROM retests r
                    INNER JOIN findings f
                        ON f.id = r.finding_id
                    WHERE f.assessment_id = ?
                `,
                [assessmentId]
            );

            await connection.execute(
                `
                    DELETE o
                    FROM finding_occurrences o
                    INNER JOIN findings f
                        ON f.id = o.finding_id
                    WHERE f.assessment_id = ?
                `,
                [assessmentId]
            );

            await connection.execute(
                `
                    DELETE FROM findings
                    WHERE assessment_id = ?
                `,
                [assessmentId]
            );

            await connection.execute(
                `
                    DELETE FROM scan_runs
                    WHERE assessment_id = ?
                `,
                [assessmentId]
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

            console.error(
                "Failed to clear scan history:",
                error
            );

            return res.status(500).json({
                error: "Failed to clear scan history.",
                message: error.message
            });
        } finally {
            if (connection) {
                connection.release();
            }
        }

        const cleanup = await cleanupEvidenceFiles(
            scanIds,
            evidenceRows
        );

        return res.json({
            message: cleanup.file_cleanup_warnings.length
                ? "Scan history cleared, but some evidence files could not be removed."
                : "Scan history and linked evidence cleared successfully.",

            assessment_id: assessmentId,

            ...counts,
            ...cleanup
        });
    }
);


// =========================================================
// DELETE ONE SCAN
// DELETE /api/scans/:assessmentId/:scanId
// =========================================================

router.delete(
    "/:assessmentId/:scanId",
    async (req, res) => {
        const assessmentId = Number(req.params.assessmentId);
        const scanId = Number(req.params.scanId);

        if (
            !Number.isInteger(assessmentId) ||
            assessmentId < 1 ||
            !Number.isInteger(scanId) ||
            scanId < 1
        ) {
            return res.status(400).json({
                error: "Invalid assessment ID or scan ID."
            });
        }

        let connection;
        let transactionStarted = false;

        let evidenceRows = [];
        let originalScanNumber = null;
        let renumberedScans = [];

        const counts = {
            deleted_scans: 0,
            deleted_findings: 0,
            deleted_occurrences: 0,
            deleted_retests: 0,
            deleted_evidence_records: 0
        };

        try {
            connection = await db.getConnection();

            await connection.beginTransaction();
            transactionStarted = true;

            const [assessmentRows] =
                await connection.query(
                    `
                        SELECT id
                        FROM assessments
                        WHERE id = ?
                        FOR UPDATE
                    `,
                    [assessmentId]
                );

            if (!assessmentRows.length) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(404).json({
                    error: "Assessment not found."
                });
            }

            const [scans] = await connection.query(
                `
                    SELECT id, scan_number, status
                    FROM scan_runs
                    WHERE id = ? AND assessment_id = ?
                    FOR UPDATE
                `,
                [scanId, assessmentId]
            );

            if (!scans.length) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(404).json({
                    error: "Scan not found for this assessment."
                });
            }

            if (
                String(scans[0].status).toLowerCase() ===
                "running"
            ) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(409).json({
                    error: "Cannot delete a scan while it is running."
                });
            }

            originalScanNumber = Number(
                scans[0].scan_number
            );

            const [findings] = await connection.query(
                `
                    SELECT id
                    FROM findings
                    WHERE assessment_id = ? AND scan_id = ?
                    FOR UPDATE
                `,
                [assessmentId, scanId]
            );

            counts.deleted_scans = 1;
            counts.deleted_findings = findings.length;

            const [occurrences] =
                await connection.query(
                    `
                        SELECT COUNT(*) AS total
                        FROM finding_occurrences o
                        INNER JOIN findings f
                            ON f.id = o.finding_id
                        WHERE
                            f.assessment_id = ?
                            AND f.scan_id = ?
                    `,
                    [assessmentId, scanId]
                );

            counts.deleted_occurrences = Number(
                occurrences[0]?.total || 0
            );

            const [retests] = await connection.query(
                `
                    SELECT COUNT(*) AS total
                    FROM retests r
                    INNER JOIN findings f
                        ON f.id = r.finding_id
                    WHERE
                        f.assessment_id = ?
                        AND f.scan_id = ?
                `,
                [assessmentId, scanId]
            );

            counts.deleted_retests = Number(
                retests[0]?.total || 0
            );

            const [storedEvidence] =
                await connection.query(
                    `
                        SELECT DISTINCT e.id, e.file_path
                        FROM evidence e
                        LEFT JOIN findings f
                            ON f.id = e.finding_id
                        WHERE
                            e.scan_id = ?
                            OR (
                                f.assessment_id = ?
                                AND f.scan_id = ?
                            )
                    `,
                    [scanId, assessmentId, scanId]
                );

            evidenceRows = storedEvidence;

            counts.deleted_evidence_records =
                evidenceRows.length;

            // Remove evidence records before their parent findings.
            await connection.execute(
                `
                    DELETE FROM evidence
                    WHERE scan_id = ?
                    OR finding_id IN (
                        SELECT id
                        FROM findings
                        WHERE assessment_id = ? AND scan_id = ?
                    )
                `,
                [scanId, assessmentId, scanId]
            );

            await connection.execute(
                `
                    DELETE r
                    FROM retests r
                    INNER JOIN findings f
                        ON f.id = r.finding_id
                    WHERE
                        f.assessment_id = ?
                        AND f.scan_id = ?
                `,
                [assessmentId, scanId]
            );

            await connection.execute(
                `
                    DELETE o
                    FROM finding_occurrences o
                    INNER JOIN findings f
                        ON f.id = o.finding_id
                    WHERE
                        f.assessment_id = ?
                        AND f.scan_id = ?
                `,
                [assessmentId, scanId]
            );

            await connection.execute(
                `
                    DELETE FROM findings
                    WHERE assessment_id = ? AND scan_id = ?
                `,
                [assessmentId, scanId]
            );

            await connection.execute(
                `
                    DELETE FROM scan_runs
                    WHERE id = ? AND assessment_id = ?
                `,
                [scanId, assessmentId]
            );

            const [remaining] = await connection.query(
                `
                    SELECT id
                    FROM scan_runs
                    WHERE assessment_id = ?
                    ORDER BY scan_number ASC, id ASC
                    FOR UPDATE
                `,
                [assessmentId]
            );

            // Use negative temporary numbers to avoid conflicts with
            // a unique (assessment_id, scan_number) key.
            await connection.execute(
                `
                    UPDATE scan_runs
                    SET scan_number = -id
                    WHERE assessment_id = ?
                `,
                [assessmentId]
            );

            renumberedScans = [];

            for (let index = 0; index < remaining.length; index += 1) {
                const remainingId = Number(
                    remaining[index].id
                );

                const newScanNumber = index + 1;

                await connection.execute(
                    `
                        UPDATE scan_runs
                        SET scan_number = ?
                        WHERE id = ? AND assessment_id = ?
                    `,
                    [
                        newScanNumber,
                        remainingId,
                        assessmentId
                    ]
                );

                renumberedScans.push({
                    id: remainingId,
                    scan_number: newScanNumber
                });
            }

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

            console.error(
                "Failed to delete individual scan:",
                error
            );

            return res.status(500).json({
                error: "Failed to delete scan.",
                message: error.message
            });
        } finally {
            if (connection) {
                connection.release();
            }
        }

        const cleanup = await cleanupEvidenceFiles(
            [scanId],
            evidenceRows
        );

        return res.json({
            message: cleanup.file_cleanup_warnings.length
                ? "Scan deleted, but some evidence files could not be removed."
                : "Scan deleted successfully. Remaining scans have been renumbered.",

            assessment_id: assessmentId,
            deleted_scan_id: scanId,
            deleted_scan_number: originalScanNumber,

            ...counts,

            remaining_scan_count: renumberedScans.length,
            renumbered_scans: renumberedScans,

            ...cleanup
        });
    }
);


// =========================================================
// EXPORT
// =========================================================

module.exports = router;