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

const severityRank = {
    Critical: 5,
    High: 4,
    Medium: 3,
    Low: 2,
    Info: 1
};

function isLocalDvwaTarget(value) {
    try {
        const url = new URL(value);

        return (
            ["http:", "https:"].includes(url.protocol) &&
            ["localhost", "127.0.0.1"].includes(url.hostname.toLowerCase()) &&
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

function getCategory(vulnerability) {
    if (!vulnerability) return "Unknown";

    if (/^Missing .* header$/i.test(vulnerability)) {
        return "Missing Security Headers";
    }

    return vulnerability;
}

function extractParameter(affectedModule) {
    const match = typeof affectedModule === "string"
        ? affectedModule.match(/\[([^\]]+)\]\s*$/)
        : null;

    return match ? match[1] : null;
}

function groupFindings(findings) {
    const groups = new Map();

    for (const finding of findings) {
        const category = getCategory(finding.vulnerability);

        if (!groups.has(category)) groups.set(category, []);
        groups.get(category).push(finding);
    }

    return Array.from(groups, ([category, items]) => ({
        category,
        items,
        severity: items.reduce(
            (highest, item) =>
                (severityRank[item.severity] || 0) >
                (severityRank[highest] || 0)
                    ? item.severity
                    : highest,
            "Info"
        )
    }));
}

function uniqueText(items, field) {
    return Array.from(
        new Set(items.map((item) => item[field]).filter(Boolean))
    ).join("\n");
}

function buildDescription(group) {
    if (group.category === "Missing Security Headers") {
        return (
            "One or more recommended HTTP security headers are missing " +
            "from scanned DVWA pages. Individual missing headers are " +
            "recorded as occurrences."
        );
    }

    return uniqueText(group.items, "description");
}

function resolveStoredUploadPath(storedPath) {
    if (!storedPath || typeof storedPath !== "string") return null;

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
    const relative = path.relative(automaticEvidenceRoot, filePath);

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
        entries = await fs.readdir(directory, { withFileTypes: true });
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

async function cleanupEvidenceFiles(scanIds, evidenceRows) {
    const warnings = [];
    let deletedAutomaticFiles = 0;
    let deletedManualFiles = 0;

    for (const scanId of scanIds) {
        const scanDirectory = path.resolve(
            automaticEvidenceRoot,
            `scan-${Number(scanId)}`
        );

        if (path.dirname(scanDirectory) !== automaticEvidenceRoot) {
            warnings.push({
                scan_id: scanId,
                message: "Unexpected automatic-evidence directory path."
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
                    message: "Unsafe file path; file was not deleted."
                });
            }
            continue;
        }

        if (isInsideAutomaticEvidence(absolutePath)) continue;

        manualFiles.set(
            `${evidence.file_path}|${absolutePath}`,
            {
                storedPath: evidence.file_path,
                absolutePath
            }
        );
    }

    for (const item of manualFiles.values()) {
        try {
            const [references] = await db.query(
                "SELECT COUNT(*) AS total FROM evidence WHERE file_path = ?",
                [item.storedPath]
            );

            if (Number(references[0]?.total || 0) > 0) continue;

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
        deleted_manual_evidence_files: deletedManualFiles,
        file_cleanup_warnings: warnings
    };
}

async function createScanRun(assessmentId) {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        const [rows] = await connection.query(
            `
                SELECT COALESCE(MAX(scan_number), 0) + 1 AS next_scan
                FROM scan_runs
                WHERE assessment_id = ?
            `,
            [assessmentId]
        );

        const scanNumber = Number(rows[0].next_scan);

        const [result] = await connection.execute(
            `
                INSERT INTO scan_runs (assessment_id, scan_number, status)
                VALUES (?, ?, 'Running')
            `,
            [assessmentId, scanNumber]
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
            summary.pages_scanned,
            summary.findings_detected,
            summary.findings_created,
            summary.duration_ms,
            scanId
        ]
    );
}

async function failScan(scanId) {
    try {
        await db.execute(
            `
                UPDATE scan_runs
                SET status = 'Failed', completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `,
            [scanId]
        );
    } catch {
        // Preserve the original scan error.
    }
}

async function createCategoryFinding(assessmentId, scanId, group) {
    const affectedModule =
        `${group.items.length} affected location(s)`;

    const [result] = await db.execute(
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open')
        `,
        [
            assessmentId,
            scanId,
            group.category,
            affectedModule,
            buildDescription(group),
            uniqueText(group.items, "observed_result"),
            uniqueText(group.items, "impact"),
            group.severity
        ]
    );

    return {
        findingId: result.insertId,
        affectedModule,
        description: buildDescription(group),
        observedResult: uniqueText(group.items, "observed_result"),
        impact: uniqueText(group.items, "impact")
    };
}

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
                item.vulnerability || "Unknown",
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
            detected_vulnerability: item.vulnerability || category,
            severity: item.severity || severity,
            affected_module: item.affected_module || null,
            parameter_name: extractParameter(item.affected_module),
            description: item.description || null,
            observed_result: item.observed_result || null,
            impact: item.impact || null,
            validation_note:
                category === "Reflected XSS"
                    ? "Input reflection was detected. Reflection alone does not prove script execution; manually validate the HTML/JavaScript context."
                    : category === "SQL Injection"
                        ? "SQL error-based detection summary; validate before treating as a confirmed exploit."
                        : "Scanner observation summary. No session cookies, passwords or complete raw HTTP response are stored."
        };

        const relativeDirectory = path.join(
            "automatic-evidence",
            `scan-${scanId}`
        );

        const absoluteDirectory = path.join(
            uploadsRoot,
            relativeDirectory
        );

        const evidenceFileName =
            `finding-${findingId}-occurrence-${occurrenceId}-${crypto.randomUUID()}.json`;

        const absoluteFilePath = path.join(
            absoluteDirectory,
            evidenceFileName
        );

        const storedFilePath = path
            .join(relativeDirectory, evidenceFileName)
            .split(path.sep)
            .join("/");

        let fileWritten = false;

        try {
            await fs.mkdir(absoluteDirectory, { recursive: true });

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
                    VALUES (?, ?, ?, 'Scan Result', ?, ?)
                `,
                [
                    findingId,
                    scanId,
                    occurrenceId,
                    storedFilePath,
                    `Automatic evidence for ${item.vulnerability || category} detected in scan #${scanNumber}.`
                ]
            );

            evidenceCreated += 1;
        } catch (error) {
            if (fileWritten) {
                try {
                    await fs.unlink(absoluteFilePath);
                } catch {
                    // Preserve the original error.
                }
            }

            console.error(
                `Unable to save evidence for occurrence #${occurrenceId}:`,
                error.message
            );
        }
    }

    return evidenceCreated;
}


// POST /api/scans/:assessmentId
router.post("/:assessmentId", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);

    if (!Number.isInteger(assessmentId) || assessmentId < 1) {
        return res.status(400).json({
            error: "Invalid assessment ID"
        });
    }

    let scanId = null;

    try {
        const [rows] = await db.query(
            "SELECT id, title, target_url FROM assessments WHERE id = ?",
            [assessmentId]
        );

        if (!rows.length) {
            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        const assessment = rows[0];

        if (!isLocalDvwaTarget(assessment.target_url)) {
            return res.status(400).json({
                error:
                    "This DVWA-only scanner accepts only the local DVWA root URL, e.g. http://localhost/DVWA/."
            });
        }

        const scan = await createScanRun(assessmentId);
        scanId = scan.scanId;

        console.log(
            `Starting Assessment #${assessmentId} - Scan #${scan.scanNumber}`
        );
        console.log(`Target: ${assessment.target_url}`);

        const started = Date.now();
        const result = await scanTarget(assessment.target_url);
        const durationMs = Date.now() - started;

        const rawFindings = Array.isArray(result.findings)
            ? result.findings
            : [];

        const groups = groupFindings(rawFindings);
        const createdCategories = [];
        let automaticEvidenceCreated = 0;

        for (const group of groups) {
            if (!group.items.length) continue;

            const finding = await createCategoryFinding(
                assessmentId,
                scanId,
                group
            );

            automaticEvidenceCreated +=
                await createOccurrencesAndEvidence({
                    findingId: finding.findingId,
                    scanId,
                    scanNumber: scan.scanNumber,
                    targetUrl: assessment.target_url,
                    category: group.category,
                    severity: group.severity,
                    items: group.items
                });

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
                    parameter_name: extractParameter(item.affected_module)
                }))
            });
        }

        const summary = {
            pages_scanned: Number(result.pages_scanned || 0),
            findings_detected: rawFindings.length,
            findings_created: createdCategories.length,
            duration_ms: durationMs
        };

        await completeScan(scanId, summary);

        await db.execute(
            "UPDATE assessments SET status = 'Completed' WHERE id = ?",
            [assessmentId]
        );

        console.log(
            `Scan #${scan.scanNumber}: ${summary.pages_scanned} pages, ` +
            `${summary.findings_detected} observations, ` +
            `${summary.findings_created} findings, ` +
            `${automaticEvidenceCreated} evidence records, ${durationMs} ms`
        );

        return res.json({
            message: "Scan completed successfully",
            assessment_id: assessmentId,
            scan_id: scanId,
            scan_number: scan.scanNumber,
            target_url: assessment.target_url,
            authenticated: result.authenticated ?? null,
            security_level: result.security_level ?? null,
            pages_scanned: summary.pages_scanned,
            html_pages_scanned: Number(result.html_pages_scanned || 0),
            javascript_files_scanned: Number(result.javascript_files_scanned || 0),
            api_endpoints_discovered: Number(result.api_endpoints_discovered || 0),
            forms_discovered: Number(result.forms_discovered || 0),
            parameters_tested: Number(result.parameters_tested || 0),
            duration_ms: summary.duration_ms,
            findings_detected: summary.findings_detected,
            findings_created: summary.findings_created,
            automatic_evidence_created: automaticEvidenceCreated,
            findings: createdCategories,
            categories: createdCategories
        });
    } catch (error) {
        console.error("Scan error:", error);

        if (scanId) await failScan(scanId);

        return res.status(500).json({
            error: "Scan failed",
            message: error.message
        });
    }
});


// GET /api/scans/:assessmentId
router.get("/:assessmentId", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);

    if (!Number.isInteger(assessmentId) || assessmentId < 1) {
        return res.status(400).json({
            error: "Invalid assessment ID"
        });
    }

    try {
        const [scans] = await db.query(
            `
                SELECT
                    id, assessment_id, scan_number, status,
                    started_at, completed_at, pages_scanned,
                    findings_detected, findings_created, duration_ms
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

        const scanMap = new Map(
            scans.map((scan) => [
                Number(scan.id),
                { ...scan, findings: [] }
            ])
        );

        const findingMap = new Map();

        for (const row of rows) {
            if (!row.scan_id) continue;

            let finding = findingMap.get(Number(row.id));

            if (!finding) {
                finding = {
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

                findingMap.set(Number(row.id), finding);

                const scan = scanMap.get(Number(row.scan_id));
                if (scan) scan.findings.push(finding);
            }

            if (row.occurrence_id) {
                finding.occurrences.push({
                    id: row.occurrence_id,
                    detected_vulnerability: row.detected_vulnerability,
                    affected_module: row.affected_module,
                    parameter_name: row.parameter_name
                });
            }
        }

        return res.json(Array.from(scanMap.values()));
    } catch (error) {
        console.error("Error loading scan history:", error);

        return res.status(500).json({
            error: "Failed to load scan history",
            message: error.message
        });
    }
});


// DELETE /api/scans/:assessmentId/history
router.delete("/:assessmentId/history", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);

    if (!Number.isInteger(assessmentId) || assessmentId < 1) {
        return res.status(400).json({
            error: "Invalid assessment ID"
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

        const [assessments] = await connection.query(
            "SELECT id FROM assessments WHERE id = ? FOR UPDATE",
            [assessmentId]
        );

        if (!assessments.length) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(404).json({
                error: "Assessment not found"
            });
        }

        const [scans] = await connection.query(
            `
                SELECT id, scan_number, status
                FROM scan_runs
                WHERE assessment_id = ?
                FOR UPDATE
            `,
            [assessmentId]
        );

        const runningScans = scans.filter(
            (scan) => String(scan.status).toLowerCase() === "running"
        );

        if (runningScans.length) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(409).json({
                error: "Cannot clear scan history while a scan is running.",
                running_scans: runningScans.map((scan) => scan.scan_number)
            });
        }

        scanIds = scans.map((scan) => Number(scan.id));
        counts.deleted_scans = scanIds.length;

        const [findings] = await connection.query(
            "SELECT id FROM findings WHERE assessment_id = ? FOR UPDATE",
            [assessmentId]
        );

        counts.deleted_findings = findings.length;

        const [occurrences] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ?
            `,
            [assessmentId]
        );

        counts.deleted_occurrences = Number(occurrences[0]?.total || 0);

        const [retests] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM retests r
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ?
            `,
            [assessmentId]
        );

        counts.deleted_retests = Number(retests[0]?.total || 0);

        const [storedEvidence] = await connection.query(
            `
                SELECT DISTINCT e.id, e.file_path
                FROM evidence e
                LEFT JOIN findings f ON f.id = e.finding_id
                LEFT JOIN scan_runs sr ON sr.id = e.scan_id
                WHERE f.assessment_id = ?
                   OR sr.assessment_id = ?
            `,
            [assessmentId, assessmentId]
        );

        evidenceRows = storedEvidence;
        counts.deleted_evidence_records = evidenceRows.length;

        await connection.execute(
            `
                DELETE e
                FROM evidence e
                LEFT JOIN findings f ON f.id = e.finding_id
                LEFT JOIN scan_runs sr ON sr.id = e.scan_id
                WHERE f.assessment_id = ?
                   OR sr.assessment_id = ?
            `,
            [assessmentId, assessmentId]
        );

        await connection.execute(
            `
                DELETE r
                FROM retests r
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ?
            `,
            [assessmentId]
        );

        await connection.execute(
            `
                DELETE o
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ?
            `,
            [assessmentId]
        );

        await connection.execute(
            "DELETE FROM findings WHERE assessment_id = ?",
            [assessmentId]
        );

        await connection.execute(
            "DELETE FROM scan_runs WHERE assessment_id = ?",
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

        console.error("Error clearing scan history:", error);

        return res.status(500).json({
            error: "Failed to clear scan history",
            message: error.message
        });
    } finally {
        if (connection) connection.release();
    }

    const cleanup = await cleanupEvidenceFiles(scanIds, evidenceRows);

    return res.json({
        message: cleanup.file_cleanup_warnings.length
            ? "Scan history cleared, but some evidence files could not be removed."
            : "Scan history and linked evidence cleared successfully.",
        assessment_id: assessmentId,
        ...counts,
        ...cleanup
    });
});


// DELETE /api/scans/:assessmentId/:scanId
router.delete("/:assessmentId/:scanId", async (req, res) => {
    const assessmentId = Number(req.params.assessmentId);
    const scanId = Number(req.params.scanId);

    if (
        !Number.isInteger(assessmentId) ||
        assessmentId < 1 ||
        !Number.isInteger(scanId) ||
        scanId < 1
    ) {
        return res.status(400).json({
            error: "Invalid assessment ID or scan ID"
        });
    }

    let connection;
    let transactionStarted = false;
    let evidenceRows = [];
    let originalScanNumber = null;
    const renumberedScans = [];

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

        const [assessments] = await connection.query(
            "SELECT id FROM assessments WHERE id = ? FOR UPDATE",
            [assessmentId]
        );

        if (!assessments.length) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(404).json({
                error: "Assessment not found"
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
                error: "Scan not found for this assessment"
            });
        }

        originalScanNumber = Number(scans[0].scan_number);

        if (String(scans[0].status).toLowerCase() === "running") {
            await connection.rollback();
            transactionStarted = false;

            return res.status(409).json({
                error: "Cannot delete a scan while it is running."
            });
        }

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

        const [occurrences] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ? AND f.scan_id = ?
            `,
            [assessmentId, scanId]
        );

        counts.deleted_occurrences = Number(occurrences[0]?.total || 0);

        const [retests] = await connection.query(
            `
                SELECT COUNT(*) AS total
                FROM retests r
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ? AND f.scan_id = ?
            `,
            [assessmentId, scanId]
        );

        counts.deleted_retests = Number(retests[0]?.total || 0);

        const [storedEvidence] = await connection.query(
            `
                SELECT DISTINCT e.id, e.file_path
                FROM evidence e
                LEFT JOIN findings f ON f.id = e.finding_id
                WHERE e.scan_id = ?
                   OR (f.assessment_id = ? AND f.scan_id = ?)
            `,
            [scanId, assessmentId, scanId]
        );

        evidenceRows = storedEvidence;
        counts.deleted_evidence_records = evidenceRows.length;

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
                INNER JOIN findings f ON f.id = r.finding_id
                WHERE f.assessment_id = ? AND f.scan_id = ?
            `,
            [assessmentId, scanId]
        );

        await connection.execute(
            `
                DELETE o
                FROM finding_occurrences o
                INNER JOIN findings f ON f.id = o.finding_id
                WHERE f.assessment_id = ? AND f.scan_id = ?
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
            "DELETE FROM scan_runs WHERE id = ? AND assessment_id = ?",
            [scanId, assessmentId]
        );

        const [remainingScans] = await connection.query(
            `
                SELECT id
                FROM scan_runs
                WHERE assessment_id = ?
                ORDER BY scan_number ASC, id ASC
                FOR UPDATE
            `,
            [assessmentId]
        );

        // Temporary negative scan numbers prevent collisions with the
        // unique (assessment_id, scan_number) key during renumbering.
        await connection.execute(
            "UPDATE scan_runs SET scan_number = -id WHERE assessment_id = ?",
            [assessmentId]
        );

        for (let index = 0; index < remainingScans.length; index += 1) {
            const id = Number(remainingScans[index].id);
            const newNumber = index + 1;

            await connection.execute(
                `
                    UPDATE scan_runs
                    SET scan_number = ?
                    WHERE id = ? AND assessment_id = ?
                `,
                [newNumber, id, assessmentId]
            );

            renumberedScans.push({
                id,
                scan_number: newNumber
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

        console.error("Failed to delete individual scan:", error);

        return res.status(500).json({
            error: "Failed to delete scan",
            message: error.message
        });
    } finally {
        if (connection) connection.release();
    }

    const cleanup = await cleanupEvidenceFiles([scanId], evidenceRows);

    return res.json({
        message: cleanup.file_cleanup_warnings.length
            ? "Scan deleted and remaining scans renumbered, but some files could not be removed."
            : "Scan deleted successfully. Remaining scans have been renumbered.",
        assessment_id: assessmentId,
        deleted_scan_id: scanId,
        deleted_scan_number: originalScanNumber,
        ...counts,
        remaining_scan_count: renumberedScans.length,
        renumbered_scans: renumberedScans,
        ...cleanup
    });
});

module.exports = router;