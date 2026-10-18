const { URL } = require("url");

// =========================================================
// DVWA SCANNER CONFIGURATION
// =========================================================

const MAX_RESOURCES = 100;
const MAX_FORMS = 60;
const REQUEST_TIMEOUT = 8000;
const MAX_BODY = 800000;

const BLOCKED_PATHS = [
    "/logout",
    "/setup.php",
    "/phpinfo.php",
    "/view_source",
    "/security.php",
    "/csrf/",
    "/upload/",
    "/delete",
    "/remove"
];

const STATIC_EXTENSIONS =
    /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz)$/i;


// =========================================================
// DVWA TARGET VALIDATION
// =========================================================

function assertDvwaRoot(value) {
    let target;

    try {
        target = new URL(value);
    } catch {
        throw new Error("Invalid target URL.");
    }

    if (!["http:", "https:"].includes(target.protocol)) {
        throw new Error(
            "The DVWA target must use HTTP or HTTPS."
        );
    }

    if (
        !["localhost", "127.0.0.1"].includes(
            target.hostname.toLowerCase()
        )
    ) {
        throw new Error(
            "DVWA-only scanner: targets must be localhost or 127.0.0.1."
        );
    }

    if (
        target.username ||
        target.password ||
        !/^\/dvwa\/?$/i.test(target.pathname) ||
        target.search ||
        target.hash
    ) {
        throw new Error(
            "DVWA-only scanner: use the local DVWA root URL, for example http://localhost/DVWA/ ."
        );
    }

    target.pathname =
        `${target.pathname.replace(/\/$/, "")}/`;

    return target;
}


// =========================================================
// SESSION CLIENT
// Maintains cookies and restricts requests to DVWA.
// =========================================================

class SessionClient {
    constructor(origin, rootPath) {
        this.origin = origin;
        this.rootPath = rootPath.toLowerCase();
        this.cookies = new Map();
    }

    setCookie(name, value) {
        this.cookies.set(name, value);
    }

    updateCookies(response) {
        let cookieHeaders = [];

        if (
            typeof response.headers.getSetCookie ===
            "function"
        ) {
            cookieHeaders =
                response.headers.getSetCookie();
        } else {
            const cookie =
                response.headers.get("set-cookie");

            if (cookie) {
                cookieHeaders = [cookie];
            }
        }

        for (const cookie of cookieHeaders) {
            const firstPart = cookie.split(";")[0];
            const splitAt = firstPart.indexOf("=");

            if (splitAt < 1) {
                continue;
            }

            this.cookies.set(
                firstPart.slice(0, splitAt).trim(),
                firstPart.slice(splitAt + 1).trim()
            );
        }
    }

    inScope(value) {
        try {
            const parsed = new URL(value, this.origin);
            const path = parsed.pathname.toLowerCase();

            return (
                parsed.origin === this.origin &&
                (
                    path === this.rootPath.slice(0, -1) ||
                    path.startsWith(this.rootPath)
                )
            );
        } catch {
            return false;
        }
    }

    async request(
        value,
        options = {},
        redirectCount = 0
    ) {
        const url =
            new URL(value, this.origin).toString();

        if (!this.inScope(url)) {
            throw new Error(
                "Blocked request outside the local DVWA application scope."
            );
        }

        if (redirectCount > 5) {
            throw new Error(
                "Too many redirects while scanning DVWA."
            );
        }

        const controller = new AbortController();

        const timer = setTimeout(
            () => controller.abort(),
            REQUEST_TIMEOUT
        );

        try {
            const headers = {
                "User-Agent":
                    "VAPT-DVWA-Scanner/1.0 (authorized-local-lab)",

                "Accept":
                    "text/html,application/xhtml+xml,*/*",

                ...(options.headers || {})
            };

            if (this.cookies.size) {
                headers.Cookie = Array.from(
                    this.cookies.entries()
                )
                    .map(([key, value]) => `${key}=${value}`)
                    .join("; ");
            }

            const response = await fetch(
                url,
                {
                    ...options,
                    headers,
                    redirect: "manual",
                    signal: controller.signal
                }
            );

            this.updateCookies(response);

            // Follow redirects only within this DVWA installation.
            if (
                response.status >= 300 &&
                response.status < 400
            ) {
                const location =
                    response.headers.get("location");

                if (location) {
                    const nextUrl =
                        new URL(location, url).toString();

                    if (!this.inScope(nextUrl)) {
                        throw new Error(
                            "Blocked redirect outside the configured DVWA application."
                        );
                    }

                    const nextOptions = {
                        ...options
                    };

                    if (
                        [301, 302, 303].includes(
                            response.status
                        )
                    ) {
                        nextOptions.method = "GET";
                        delete nextOptions.body;
                    }

                    return this.request(
                        nextUrl,
                        nextOptions,
                        redirectCount + 1
                    );
                }
            }

            const body = await response.text();

            return {
                url: response.url || url,
                status: response.status,

                headers: Object.fromEntries(
                    response.headers.entries()
                ),

                body: body.slice(0, MAX_BODY)
            };
        } finally {
            clearTimeout(timer);
        }
    }
}


// =========================================================
// HTTP HELPERS
// =========================================================

async function fetchPage(client, url) {
    return client.request(
        url,
        { method: "GET" }
    );
}

async function postForm(client, url, data) {
    const body = new URLSearchParams();

    for (const [key, value] of Object.entries(data)) {
        body.append(
            key,
            value == null ? "" : String(value)
        );
    }

    return client.request(
        url,
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },

            body: body.toString()
        }
    );
}


// =========================================================
// URL SCOPE AND NORMALIZATION
// =========================================================

function inDvwaPath(value, rootUrl) {
    try {
        const parsed = new URL(value, rootUrl);
        const root = new URL(rootUrl);

        return (
            parsed.origin === root.origin &&
            (
                parsed.pathname.toLowerCase() ===
                    root.pathname.slice(0, -1).toLowerCase() ||
                parsed.pathname.toLowerCase().startsWith(
                    root.pathname.toLowerCase()
                )
            )
        );
    } catch {
        return false;
    }
}

function normalizeUrl(value, baseUrl, rootUrl) {
    if (!value) {
        return null;
    }

    const trimmed = String(value).trim();

    if (
        !trimmed ||
        /^(?:#|javascript:|mailto:|tel:|data:)/i.test(
            trimmed
        )
    ) {
        return null;
    }

    try {
        const parsed = new URL(trimmed, baseUrl);

        parsed.hash = "";

        if (
            !inDvwaPath(parsed.toString(), rootUrl)
        ) {
            return null;
        }

        if (STATIC_EXTENSIONS.test(parsed.pathname)) {
            return null;
        }

        if (
            BLOCKED_PATHS.some(
                (part) =>
                    parsed.pathname.toLowerCase().includes(part)
            )
        ) {
            return null;
        }

        return parsed.toString();
    } catch {
        return null;
    }
}


// =========================================================
// HTML ATTRIBUTE PARSING
// =========================================================

function getAttributes(text) {
    const attrs = {};

    const regex =
        /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;

    let match;

    while (
        (match = regex.exec(text || "")) !== null
    ) {
        const key = match[1].toLowerCase();

        attrs[key] =
            match[2] ??
            match[3] ??
            match[4] ??
            "";
    }

    return attrs;
}


// =========================================================
// DISCOVER DVWA LINKS
// =========================================================

function discoverLinks(html, baseUrl, rootUrl) {
    const links = new Set();
    const regex = /<a\b([^>]*)>/gi;

    let match;

    while (
        (match = regex.exec(html)) !== null
    ) {
        const attrs = getAttributes(match[1]);

        const link = normalizeUrl(
            attrs.href,
            baseUrl,
            rootUrl
        );

        if (link) {
            links.add(link);
        }
    }

    return Array.from(links);
}


// =========================================================
// DISCOVER FORMS AND INPUT PARAMETERS
// =========================================================

function discoverForms(html, baseUrl, rootUrl) {
    const forms = [];

    const formRegex =
        /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;

    let match;

    while (
        (match = formRegex.exec(html)) !== null &&
        forms.length < MAX_FORMS
    ) {
        const formAttrs = getAttributes(match[1]);

        const action = normalizeUrl(
            formAttrs.action || baseUrl,
            baseUrl,
            rootUrl
        );

        if (!action) {
            continue;
        }

        const body = match[2] || "";
        const inputs = [];

        // INPUT elements
        const inputRegex = /<input\b([^>]*)>/gi;
        let inputMatch;

        while (
            (inputMatch = inputRegex.exec(body)) !== null
        ) {
            const attrs = getAttributes(inputMatch[1]);

            if (!attrs.name) {
                continue;
            }

            inputs.push({
                name: attrs.name,
                type: (attrs.type || "text").toLowerCase(),
                value: attrs.value || ""
            });
        }

        // TEXTAREA elements
        const textareaRegex =
            /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;

        let areaMatch;

        while (
            (areaMatch = textareaRegex.exec(body)) !== null
        ) {
            const attrs = getAttributes(areaMatch[1]);

            if (attrs.name) {
                inputs.push({
                    name: attrs.name,
                    type: "textarea",
                    value: areaMatch[2].trim()
                });
            }
        }

        // SELECT elements
        const selectRegex =
            /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;

        let selectMatch;

        while (
            (selectMatch = selectRegex.exec(body)) !== null
        ) {
            const attrs = getAttributes(selectMatch[1]);

            if (!attrs.name) {
                continue;
            }

            const option =
                /<option\b([^>]*)>([\s\S]*?)<\/option>/i.exec(
                    selectMatch[2]
                );

            const optionAttrs = option
                ? getAttributes(option[1])
                : {};

            inputs.push({
                name: attrs.name,
                type: "select",

                value:
                    optionAttrs.value ||
                    (option ? option[2].trim() : "1")
            });
        }

        if (!inputs.length) {
            continue;
        }

        forms.push({
            action,

            method:
                (formAttrs.method || "GET").toUpperCase() === "POST"
                    ? "POST"
                    : "GET",

            source: baseUrl,
            inputs
        });
    }

    return forms;
}


// =========================================================
// SQL ERROR SIGNATURES
// =========================================================

function looksLikeSqlError(body) {
    const signatures = [
        /sql syntax/i,
        /mysql_fetch/i,
        /mysqli?.*error/i,
        /you have an error in your sql syntax/i,
        /warning.*mysql/i,
        /unclosed quotation mark/i,
        /odbc sql/i,
        /pdoexception/i,
        /sqlstate/i,
        /sqlite.*error/i,
        /postgresql.*error/i
    ];

    return signatures.some(
        (pattern) => pattern.test(body || "")
    );
}


// =========================================================
// FINDING DEDUPLICATION
// =========================================================

function addFinding(findings, seen, finding) {
    const key =
        `${finding.vulnerability}|${finding.affected_module}`;

    if (seen.has(key)) {
        return;
    }

    seen.add(key);
    findings.push(finding);
}


// =========================================================
// BUILD QUERY PARAMETERS
// =========================================================

function buildQuery(url, parameter, value) {
    const parsed = new URL(url);

    parsed.searchParams.set(
        parameter,
        value
    );

    return parsed.toString();
}


// =========================================================
// BUILD FORM DATA
// Preserves hidden tokens and submit controls, but does
// not actively test passwords, files, checkboxes or radios.
// =========================================================

function buildFormData(form, testedParameter, testedValue) {
    const data = {};

    for (const input of form.inputs) {
        const type = input.type.toLowerCase();

        if (
            [
                "file",
                "password",
                "button",
                "reset",
                "checkbox",
                "radio"
            ].includes(type)
        ) {
            continue;
        }

        if (type === "submit") {
            data[input.name] =
                input.value || "Submit";
        } else {
            data[input.name] =
                input.name === testedParameter
                    ? testedValue
                    : (input.value || "1");
        }
    }

    return data;
}


// =========================================================
// SEND A TEST REQUEST
// =========================================================

async function issueTestRequest(
    client,
    requestInfo,
    parameter,
    value
) {
    if (requestInfo.form) {
        const data = buildFormData(
            requestInfo.form,
            parameter,
            value
        );

        if (requestInfo.method === "POST") {
            return postForm(
                client,
                requestInfo.url,
                data
            );
        }

        const url = new URL(requestInfo.url);

        for (const [key, fieldValue] of Object.entries(data)) {
            url.searchParams.set(
                key,
                String(fieldValue)
            );
        }

        return fetchPage(
            client,
            url.toString()
        );
    }

    return fetchPage(
        client,
        buildQuery(
            requestInfo.url,
            parameter,
            value
        )
    );
}


// =========================================================
// REFLECTED XSS TEST
// This checks marker reflection; manually validate the
// HTML context before treating it as confirmed executable XSS.
// =========================================================

async function testXss(
    client,
    requestInfo,
    parameter,
    findings,
    seen
) {
    const marker =
        `VAPT_REFLECT_${Math.random().toString(36).slice(2, 10)}`;

    const payload = `"><vapt-${marker}>`;

    try {
        const response = await issueTestRequest(
            client,
            requestInfo,
            parameter,
            payload
        );

        if (!response.body.includes(marker)) {
            return;
        }

        addFinding(findings, seen, {
            vulnerability: "Reflected XSS",

            affected_module:
                `${new URL(requestInfo.url).pathname} [${parameter}]`,

            description:
                "A unique marker submitted through an application input was reflected in the HTTP response. Reflection alone is an indicator and should be manually validated for executable HTML/JavaScript context.",

            observed_result:
                `The unique marker ${marker} was returned after testing parameter ${parameter}.`,

            impact:
                "If the reflected value reaches an executable HTML or script context without appropriate encoding, it may allow client-side script injection.",

            severity: "High",
            status: "Open"
        });
    } catch {
        // Continue scanning if an individual input fails.
    }
}


// =========================================================
// SQL INJECTION TEST
// Error-based signature testing; blind SQL injection is not
// covered by this basic detector.
// =========================================================

async function testSqlInjection(
    client,
    requestInfo,
    parameter,
    findings,
    seen
) {
    const payloads = [
        "'",
        '"',
        "1' OR '1'='1",
        "1' OR '1'='2"
    ];

    for (const payload of payloads) {
        try {
            const response = await issueTestRequest(
                client,
                requestInfo,
                parameter,
                payload
            );

            if (!looksLikeSqlError(response.body)) {
                continue;
            }

            addFinding(findings, seen, {
                vulnerability: "SQL Injection",

                affected_module:
                    `${new URL(requestInfo.url).pathname} [${parameter}]`,

                description:
                    "A controlled SQL metacharacter or test expression caused SQL-related error indicators in the response.",

                observed_result:
                    `SQL error indicators were detected after testing parameter ${parameter} with a controlled SQL payload.`,

                impact:
                    "If confirmed, SQL injection may permit query manipulation or unauthorized database access.",

                severity: "High",
                status: "Open"
            });

            return;
        } catch {
            // Continue with other SQL payloads.
        }
    }
}


// =========================================================
// TEST FORM INPUTS
// =========================================================

async function testForm(
    client,
    form,
    findings,
    seen
) {
    let testedCount = 0;

    const excluded = [
        "hidden",
        "submit",
        "button",
        "reset",
        "file",
        "password",
        "checkbox",
        "radio"
    ];

    const inputs = form.inputs.filter(
        (input) =>
            !excluded.includes(input.type.toLowerCase())
    );

    for (const input of inputs) {
        testedCount += 1;

        const requestInfo = {
            method: form.method,
            url: form.action,
            form
        };

        await testXss(
            client,
            requestInfo,
            input.name,
            findings,
            seen
        );

        await testSqlInjection(
            client,
            requestInfo,
            input.name,
            findings,
            seen
        );
    }

    return testedCount;
}


// =========================================================
// TEST EXISTING URL PARAMETERS
// =========================================================

async function testUrlParameters(
    client,
    pageUrl,
    findings,
    seen
) {
    const url = new URL(pageUrl);

    const parameters = Array.from(
        new Set(url.searchParams.keys())
    );

    for (const parameter of parameters) {
        const requestInfo = {
            method: "GET",
            url: pageUrl
        };

        await testXss(
            client,
            requestInfo,
            parameter,
            findings,
            seen
        );

        await testSqlInjection(
            client,
            requestInfo,
            parameter,
            findings,
            seen
        );
    }

    return parameters.length;
}


// =========================================================
// DVWA LOGIN TOKEN
// =========================================================

function extractUserToken(html) {
    const patterns = [
        /name\s*=\s*["']user_token["'][^>]*value\s*=\s*["']([^"']+)["']/i,
        /value\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']user_token["']/i
    ];

    for (const pattern of patterns) {
        const match = pattern.exec(html || "");

        if (match) {
            return match[1];
        }
    }

    return null;
}


// =========================================================
// DVWA AUTHENTICATION
// =========================================================

async function loginToDvwa(client, rootUrl) {
    const loginUrl =
        new URL("login.php", rootUrl).toString();

    const loginPage = await fetchPage(
        client,
        loginUrl
    );

    const token = extractUserToken(
        loginPage.body
    );

    if (!token) {
        throw new Error(
            "DVWA login token was not found on login.php. Verify the DVWA URL and that DVWA is running."
        );
    }

    const username =
        process.env.DVWA_USERNAME || "admin";

    const password =
        process.env.DVWA_PASSWORD || "password";

    const loginResponse = await postForm(
        client,
        loginUrl,
        {
            username,
            password,
            Login: "Login",
            user_token: token
        }
    );

    if (
        /name\s*=\s*["']username["']/i.test(
            loginResponse.body
        ) &&
        /login/i.test(loginResponse.body)
    ) {
        throw new Error(
            "DVWA login failed. Check DVWA_USERNAME and DVWA_PASSWORD in backend/.env."
        );
    }

    const securityLevel =
        (process.env.DVWA_SECURITY_LEVEL || "low").toLowerCase();

    if (
        ["low", "medium", "high", "impossible"].includes(
            securityLevel
        )
    ) {
        client.setCookie(
            "security",
            securityLevel
        );
    }

    const dashboard = await fetchPage(
        client,
        new URL("index.php", rootUrl).toString()
    );

    if (
        !/logout/i.test(dashboard.body) &&
        !/security level:/i.test(dashboard.body)
    ) {
        throw new Error(
            "DVWA authentication could not be verified after login."
        );
    }

    return {
        loginUrl,
        username,
        securityLevel
    };
}


// =========================================================
// SECURITY HEADER CHECKS
// =========================================================

function checkSecurityHeaders(
    response,
    findings,
    seen
) {
    const tests = [
        [
            "x-content-type-options",
            "Missing X-Content-Type-Options header"
        ],
        [
            "content-security-policy",
            "Missing Content-Security-Policy header"
        ],
        [
            "referrer-policy",
            "Missing Referrer-Policy header"
        ]
    ];

    const path = new URL(response.url).pathname;

    for (const [headerName, title] of tests) {
        if (response.headers[headerName]) {
            continue;
        }

        addFinding(findings, seen, {
            vulnerability: title,

            affected_module: path,

            description:
                "The HTTP response does not include a recommended browser security header.",

            observed_result:
                `${headerName} was absent from the response.`,

            impact:
                "Missing browser security controls can increase exposure to some client-side attacks; impact depends on the application and deployment context.",

            severity: "Low",
            status: "Open"
        });
    }
}


// =========================================================
// SHOULD CRAWL URL?
// =========================================================

function shouldCrawl(url, rootUrl) {
    if (!inDvwaPath(url, rootUrl)) {
        return false;
    }

    try {
        const parsed = new URL(url);

        if (STATIC_EXTENSIONS.test(parsed.pathname)) {
            return false;
        }

        return !BLOCKED_PATHS.some(
            (part) =>
                parsed.pathname.toLowerCase().includes(part)
        );
    } catch {
        return false;
    }
}


// =========================================================
// MAIN DVWA SCANNER
// =========================================================

async function scanTarget(targetUrl) {
    const startedAt = Date.now();

    const target = assertDvwaRoot(targetUrl);
    const normalizedTargetUrl = target.toString();

    const client = new SessionClient(
        target.origin,
        target.pathname
    );

    // Always authenticate to DVWA before scanning.
    const authentication = await loginToDvwa(
        client,
        normalizedTargetUrl
    );

    const authenticated = true;
    const securityLevel = authentication.securityLevel;

    const queue = [normalizedTargetUrl];
    const discovered = new Set(queue);
    const testedFormKeys = new Set();

    const findings = [];
    const seenFindings = new Set();
    const pages = [];

    let htmlPagesScanned = 0;
    let formsDiscovered = 0;
    let parametersTested = 0;

    while (
        queue.length &&
        pages.length < MAX_RESOURCES
    ) {
        const current = queue.shift();

        if (!shouldCrawl(current, normalizedTargetUrl)) {
            continue;
        }

        try {
            const response = await fetchPage(
                client,
                current
            );

            pages.push({
                url: response.url,
                status: response.status
            });

            const contentType =
                (response.headers["content-type"] || "").toLowerCase();

            const looksLikeHtml =
                /<(?:!doctype\s+html|html|form|a)\b/i.test(
                    response.body
                );

            if (
                !contentType.includes("text/html") &&
                !looksLikeHtml
            ) {
                continue;
            }

            htmlPagesScanned += 1;

            checkSecurityHeaders(
                response,
                findings,
                seenFindings
            );

            // Discover more DVWA pages.
            const links = discoverLinks(
                response.body,
                response.url,
                normalizedTargetUrl
            );

            for (const link of links) {
                if (discovered.size >= MAX_RESOURCES) {
                    break;
                }

                if (
                    !discovered.has(link) &&
                    shouldCrawl(link, normalizedTargetUrl)
                ) {
                    discovered.add(link);
                    queue.push(link);
                }
            }

            // Discover and test unique forms.
            const forms = discoverForms(
                response.body,
                response.url,
                normalizedTargetUrl
            );

            for (const form of forms) {
                const formKey = [
                    form.method,
                    form.action,
                    form.inputs
                        .map(
                            (input) =>
                                `${input.name}:${input.type}`
                        )
                        .join(",")
                ].join("|");

                if (testedFormKeys.has(formKey)) {
                    continue;
                }

                testedFormKeys.add(formKey);
                formsDiscovered += 1;

                parametersTested += await testForm(
                    client,
                    form,
                    findings,
                    seenFindings
                );
            }

            parametersTested += await testUrlParameters(
                client,
                response.url,
                findings,
                seenFindings
            );
        } catch (error) {
            pages.push({
                url: current,
                status: "error",

                error:
                    error.name === "AbortError"
                        ? "timeout"
                        : error.message
            });
        }
    }

    const durationMs = Date.now() - startedAt;

    return {
        target_url: normalizedTargetUrl,

        authenticated,
        authentication,
        security_level: securityLevel,

        pages_scanned: pages.length,
        html_pages_scanned: htmlPagesScanned,

        // Retained for compatibility with the frontend.
        javascript_files_scanned: 0,
        api_endpoints_discovered: 0,

        forms_discovered: formsDiscovered,
        parameters_tested: parametersTested,

        duration_ms: durationMs,

        findings,
        pages,

        discovered_api_endpoints: [],
        javascript_files: []
    };
}


// =========================================================
// EXPORT
// =========================================================

module.exports = {
    scanTarget
};