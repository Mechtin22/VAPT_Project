const { URL } = require("url");

// =========================================================
// DVWA-ONLY ACTIVE SCANNER
// Scope: http(s)://localhost/DVWA or 127.0.0.1/DVWA.
// State-changing tests are avoided by default. The stored-XSS
// guestbook form is inspected, not submitted.
// =========================================================

const MAX_RESOURCES = 160;
const MAX_FORMS = 80;
const REQUEST_TIMEOUT = 8000;
const MAX_BODY = 1000000;
const USER_AGENT = "VAPT-DVWA-Scanner/3.0 (authorized-local-lab)";
const SECURITY_LEVELS = ["low", "medium", "high", "impossible"];

const DVWA_MODULES = [
    "vulnerabilities/brute/",
    "vulnerabilities/exec/",
    "vulnerabilities/csrf/",
    "vulnerabilities/fi/?page=include.php",
    "vulnerabilities/upload/",
    "vulnerabilities/captcha/",
    "vulnerabilities/sqli/",
    "vulnerabilities/sqli_blind/",
    "vulnerabilities/weak_id/",
    "vulnerabilities/xss_d/",
    "vulnerabilities/xss_r/",
    "vulnerabilities/xss_s/",
    "vulnerabilities/csp/",
    "vulnerabilities/javascript/",
    "vulnerabilities/authbypass/",
    "vulnerabilities/open_redirect/",
    "vulnerabilities/cryptography/",
    "vulnerabilities/api/"
];

const BLOCKED_PATHS = [
    "/logout",
    "/setup.php",
    "/phpinfo.php",
    "/view_source",
    "/view_help.php",
    "/delete",
    "/remove"
];

const STATIC_EXTENSIONS =
    /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|gz)$/i;


// =========================================================
// VALIDATE TARGET
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
            "DVWA-only scanner: target must be localhost or 127.0.0.1."
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
            "DVWA-only scanner: use the local DVWA root URL, " +
            "for example http://localhost/DVWA/."
        );
    }

    target.pathname =
        `${target.pathname.replace(/\/+$/, "")}/`;

    return target;
}


// =========================================================
// DVWA SCOPE ENFORCEMENT
// =========================================================

function isWithinDvwaScope(value, baseUrl) {
    try {
        const candidate = new URL(value);
        const base = new URL(baseUrl);

        const rootPath = base.pathname
            .replace(/\/+$/, "")
            .toLowerCase();

        const candidatePath =
            candidate.pathname.toLowerCase();

        return (
            candidate.origin === base.origin &&
            (
                candidatePath === rootPath ||
                candidatePath.startsWith(`${rootPath}/`)
            )
        );
    } catch {
        return false;
    }
}


// =========================================================
// SET-COOKIE PARSING
// =========================================================

function getSetCookieHeaders(headers) {
    if (typeof headers.getSetCookie === "function") {
        return headers.getSetCookie();
    }

    const combined = headers.get("set-cookie");

    if (!combined) {
        return [];
    }

    // Preserve commas in Expires attributes where possible.
    return combined.split(
        /,(?=\s*[^;,=\s]+=[^;,]+)/g
    );
}


// =========================================================
// SESSION CLIENT
// =========================================================

class SessionClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.origin = new URL(baseUrl).origin;
        this.rootPath =
            new URL(baseUrl).pathname.toLowerCase();

        this.cookies = new Map();
        this.cookieHeaders = new Map();
    }

    setCookie(name, value) {
        this.cookies.set(name, value);
    }

    updateCookies(response) {
        const setCookies =
            getSetCookieHeaders(response.headers);

        for (const cookie of setCookies) {
            const firstPart = cookie.split(";")[0];
            const equalsAt = firstPart.indexOf("=");

            if (equalsAt < 1) {
                continue;
            }

            const name = firstPart
                .slice(0, equalsAt)
                .trim();

            const value = firstPart
                .slice(equalsAt + 1)
                .trim();

            if (name) {
                this.cookies.set(name, value);
                this.cookieHeaders.set(
                    name,
                    cookie.trim()
                );
            }
        }

        return setCookies;
    }

    cookieHeader() {
        return Array.from(this.cookies.entries())
            .map(
                ([name, value]) =>
                    `${name}=${value}`
            )
            .join("; ");
    }

    async request(
        value,
        options = {},
        redirectCount = 0
    ) {
        const url = new URL(
            value,
            this.baseUrl
        ).toString();

        if (!isWithinDvwaScope(url, this.baseUrl)) {
            throw new Error(
                "Blocked request outside local DVWA scope."
            );
        }

        if (redirectCount > 5) {
            throw new Error(
                "Too many redirects while scanning DVWA."
            );
        }

        const inspectRedirect =
            options.inspectRedirect === true;

        const fetchOptions = { ...options };

        delete fetchOptions.inspectRedirect;

        const controller = new AbortController();

        const timer = setTimeout(
            () => controller.abort(),
            REQUEST_TIMEOUT
        );

        try {
            const headers = {
                "User-Agent": USER_AGENT,
                "Accept":
                    "text/html,application/xhtml+xml,application/json,*/*",
                ...(fetchOptions.headers || {})
            };

            const cookies = this.cookieHeader();

            if (cookies) {
                headers.Cookie = cookies;
            }

            const response = await fetch(
                url,
                {
                    ...fetchOptions,
                    headers,
                    redirect: "manual",
                    signal: controller.signal
                }
            );

            const setCookies =
                this.updateCookies(response);

            const location =
                response.headers.get("location");

            const isRedirect =
                response.status >= 300 &&
                response.status < 400;

            // Redirect checks can inspect Location without following
            // a potentially external destination.
            if (
                isRedirect &&
                location &&
                inspectRedirect
            ) {
                const body = await response.text();

                return {
                    url: response.url || url,
                    status: response.status,
                    headers: Object.fromEntries(
                        response.headers.entries()
                    ),
                    setCookies,
                    location,
                    body: body.slice(0, MAX_BODY)
                };
            }

            if (isRedirect && location) {
                const nextUrl = new URL(
                    location,
                    url
                ).toString();

                if (
                    !isWithinDvwaScope(
                        nextUrl,
                        this.baseUrl
                    )
                ) {
                    throw new Error(
                        "Blocked redirect outside the configured local DVWA application."
                    );
                }

                const nextOptions = {
                    ...fetchOptions
                };

                if ([301, 302, 303].includes(response.status)) {
                    nextOptions.method = "GET";
                    delete nextOptions.body;
                }

                return this.request(
                    nextUrl,
                    nextOptions,
                    redirectCount + 1
                );
            }

            const body = await response.text();

            return {
                url: response.url || url,
                status: response.status,
                headers: Object.fromEntries(
                    response.headers.entries()
                ),
                setCookies,
                location,
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
// URL HELPERS
// =========================================================

function getDvwaBaseUrl(targetUrl) {
    const target = new URL(targetUrl);

    if (!target.pathname.endsWith("/")) {
        target.pathname += "/";
    }

    return target.origin + target.pathname;
}

function normalizeUrl(value, baseUrl) {
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

        return parsed.toString();
    } catch {
        return null;
    }
}

function responsePath(response) {
    try {
        return new URL(response.url).pathname;
    } catch {
        return "/";
    }
}

function moduleNameFromPath(pathname) {
    const match = pathname
        .toLowerCase()
        .match(/\/vulnerabilities\/([^/]+)\//);

    return match ? match[1] : "";
}

function sameHost(first, second) {
    try {
        return (
            new URL(first).host ===
            new URL(second).host
        );
    } catch {
        return false;
    }
}


// =========================================================
// HTML ATTRIBUTE PARSING
// =========================================================

function getAttribute(source, name) {
    const escaped = name.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );

    const regex = new RegExp(
        `(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
        "i"
    );

    const match = regex.exec(source || "");

    return match
        ? (match[1] ?? match[2] ?? match[3] ?? "")
        : "";
}


// =========================================================
// LINK DISCOVERY
// =========================================================

function discoverLinks(
    html,
    baseUrl,
    rootUrl
) {
    const links = new Set();
    const regex = /<a\b([^>]*)>/gi;

    let match;

    while (
        (match = regex.exec(html || "")) !== null
    ) {
        const attrs = match[1] || "";

        const raw = getAttribute(
            attrs,
            "href"
        );

        const normalized = normalizeUrl(
            raw,
            baseUrl
        );

        if (
            normalized &&
            isWithinDvwaScope(normalized, rootUrl) &&
            !STATIC_EXTENSIONS.test(
                new URL(normalized).pathname
            )
        ) {
            links.add(normalized);
        }
    }

    return Array.from(links);
}


// =========================================================
// FORM DISCOVERY
// =========================================================

function discoverForms(
    html,
    baseUrl,
    rootUrl
) {
    const forms = [];

    const formRegex =
        /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;

    let match;

    while (
        (match = formRegex.exec(html || "")) !== null &&
        forms.length < MAX_FORMS
    ) {
        const formAttrs = match[1] || "";
        const formBody = match[2] || "";

        const rawAction = getAttribute(
            formAttrs,
            "action"
        );

        const action = normalizeUrl(
            rawAction || baseUrl,
            baseUrl
        );

        if (
            !action ||
            !isWithinDvwaScope(action, rootUrl)
        ) {
            continue;
        }

        const method =
            (
                getAttribute(formAttrs, "method") ||
                "GET"
            ).toUpperCase() === "POST"
                ? "POST"
                : "GET";

        const enctype = getAttribute(
            formAttrs,
            "enctype"
        ).toLowerCase();

        const inputs = [];

        // Inputs
        const inputRegex = /<input\b([^>]*)>/gi;
        let inputMatch;

        while (
            (inputMatch = inputRegex.exec(formBody)) !== null
        ) {
            const attrs = inputMatch[1] || "";

            const name = getAttribute(
                attrs,
                "name"
            );

            if (!name) {
                continue;
            }

            inputs.push({
                name,
                type: (
                    getAttribute(attrs, "type") ||
                    "text"
                ).toLowerCase(),
                value: getAttribute(attrs, "value"),
                accept: getAttribute(attrs, "accept")
            });
        }

        // Textareas
        const textareaRegex =
            /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;

        let textareaMatch;

        while (
            (textareaMatch =
                textareaRegex.exec(formBody)) !== null
        ) {
            const name = getAttribute(
                textareaMatch[1] || "",
                "name"
            );

            if (name) {
                inputs.push({
                    name,
                    type: "textarea",
                    value: (
                        textareaMatch[2] || ""
                    ).trim()
                });
            }
        }

        // Select controls
        const selectRegex =
            /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;

        let selectMatch;

        while (
            (selectMatch =
                selectRegex.exec(formBody)) !== null
        ) {
            const name = getAttribute(
                selectMatch[1] || "",
                "name"
            );

            if (!name) {
                continue;
            }

            const optionMatch = /<option\b([^>]*)>([\s\S]*?)<\/option>/i
                .exec(selectMatch[2] || "");

            const optionValue = optionMatch
                ? getAttribute(
                    optionMatch[1] || "",
                    "value"
                )
                : "";

            const optionText = optionMatch
                ? (optionMatch[2] || "").trim()
                : "1";

            inputs.push({
                name,
                type: "select",
                value: optionValue || optionText || "1"
            });
        }

        // Named submit buttons
        const buttonRegex =
            /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;

        let buttonMatch;

        while (
            (buttonMatch =
                buttonRegex.exec(formBody)) !== null
        ) {
            const attrs = buttonMatch[1] || "";
            const name = getAttribute(attrs, "name");

            if (!name) {
                continue;
            }

            inputs.push({
                name,
                type: "submit",
                value:
                    getAttribute(attrs, "value") ||
                    (buttonMatch[2] || "").trim() ||
                    "Submit"
            });
        }

        forms.push({
            action,
            method,
            enctype,
            source: baseUrl,
            inputs
        });
    }

    return forms;
}


// =========================================================
// FINDING DEDUPLICATION
// =========================================================

function addFinding(
    findings,
    seen,
    finding
) {
    const key =
        `${finding.vulnerability}|${finding.affected_module}`;

    if (seen.has(key)) {
        return;
    }

    seen.add(key);

    findings.push({
        confidence: finding.confidence || "Medium",
        status: finding.status || "Open",
        ...finding
    });
}

function isLikelyHtml(response) {
    const contentType = String(
        response.headers["content-type"] || ""
    ).toLowerCase();

    return (
        contentType.includes("text/html") ||
        /<(?:!doctype\s+html|html|form|a)\b/i.test(
            response.body || ""
        )
    );
}


// =========================================================
// SECURITY HEADER AND RESPONSE CHECKS
// =========================================================

function checkSecurityHeaders(
    response,
    findings,
    seen
) {
    const headers = response.headers || {};
    const path = responsePath(response);

    const checks = [
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

    for (const [header, title] of checks) {
        if (!headers[header]) {
            addFinding(findings, seen, {
                vulnerability: title,
                affected_module: path,
                description:
                    `The HTTP response does not include ${header}. ` +
                    "This is a hardening observation; assess practical impact in context.",
                observed_result:
                    `${header} was absent from the response at ${path}.`,
                impact:
                    "Missing browser security headers can weaken protection against certain client-side attacks.",
                severity: "Low",
                confidence: "High"
            });
        }
    }

    const csp = String(
        headers["content-security-policy"] || ""
    );

    if (
        !headers["x-frame-options"] &&
        !/frame-ancestors\s+[^;]+/i.test(csp)
    ) {
        addFinding(findings, seen, {
            vulnerability: "Missing Clickjacking Protection",
            affected_module: path,
            description:
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            observed_result:
                "No framing restriction was observed in the response headers.",
            impact:
                "The page may be embeddable by another site; exploitability depends on the user interface and browser behavior.",
            severity: "Low",
            confidence: "High"
        });
    }

    if (
        csp &&
        /(?:^|[;\s])(?:'unsafe-inline'|'unsafe-eval'|\*)/i.test(csp)
    ) {
        addFinding(findings, seen, {
            vulnerability: "Weak Content Security Policy",
            affected_module: path,
            description:
                "The Content-Security-Policy includes a broad wildcard or unsafe script directive.",
            observed_result:
                `Observed CSP: ${csp.slice(0, 300)}`,
            impact:
                "A permissive CSP provides less defense-in-depth against script injection than a strict policy.",
            severity: "Low",
            confidence: "Medium"
        });
    }

    const allowOrigin =
        headers["access-control-allow-origin"];

    const allowCredentials = String(
        headers["access-control-allow-credentials"] || ""
    ).toLowerCase();

    if (
        allowOrigin === "*" &&
        allowCredentials === "true"
    ) {
        addFinding(findings, seen, {
            vulnerability: "Potentially Unsafe CORS Configuration",
            affected_module: path,
            description:
                "The response appears to combine a wildcard CORS origin with credentialed requests.",
            observed_result:
                "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true were observed.",
            impact:
                "CORS policy mistakes can expose response data to untrusted websites; verify browser behavior and actual response headers.",
            severity: "Medium",
            confidence: "High"
        });
    }

    for (const [headerName, value] of [
        ["Server", headers.server],
        ["X-Powered-By", headers["x-powered-by"]]
    ]) {
        if (value) {
            addFinding(findings, seen, {
                vulnerability: "Server Technology Information Disclosure",
                affected_module:
                    `${path} [${headerName.toLowerCase()}]`,
                description:
                    "The response reveals a server or framework banner. Disclosure alone does not prove a software vulnerability.",
                observed_result:
                    `${headerName}: ${String(value).slice(0, 180)}`,
                impact:
                    "Technology banners can make platform fingerprinting easier and help an attacker select follow-up tests.",
                severity: "Info",
                confidence: "High"
            });
        }
    }

    const body = String(response.body || "");

    if (
        /(?:Fatal error|Warning: .* on line \d+|Stack trace:|Traceback \(most recent call last\))/i.test(body)
    ) {
        const errorMatch = body.match(
            /(?:Fatal error|Warning: .* on line \d+|Stack trace:|Traceback \(most recent call last\))/i
        );

        addFinding(findings, seen, {
            vulnerability: "Verbose Error or Stack Trace Disclosure",
            affected_module: path,
            description:
                "The response contains markers associated with detailed application errors or stack traces.",
            observed_result:
                errorMatch?.[0] || "Error-detail marker found.",
            impact:
                "Detailed errors can expose internal paths, query logic, or implementation details that support further attacks.",
            severity: "Low",
            confidence: "Medium"
        });
    }

    if (/phpinfo\(\)|PHP Version\s+\d+\.\d+/i.test(body)) {
        addFinding(findings, seen, {
            vulnerability: "PHP Information Page Exposure",
            affected_module: path,
            description:
                "The response resembles a PHP information page.",
            observed_result:
                "PHP version or phpinfo markers were present in the response.",
            impact:
                "Runtime configuration information can reveal paths, modules, environment settings, and version data.",
            severity: "Medium",
            confidence: "High"
        });
    }

    if (
        /(?:\/var\/www\/|C:\\xampp\\|C:\\wamp\\|\/home\/[^\s<>]+\/public_html\/)/i.test(body)
    ) {
        addFinding(findings, seen, {
            vulnerability: "Absolute Server Path Disclosure",
            affected_module: path,
            description:
                "The response appears to contain an absolute server filesystem path.",
            observed_result:
                "A server filesystem path pattern was observed in the response.",
            impact:
                "Filesystem paths reveal deployment details and can support targeted file inclusion or path traversal attempts.",
            severity: "Low",
            confidence: "Medium"
        });
    }
}


// =========================================================
// COOKIE SECURITY CHECKS
// =========================================================

function checkCookieSecurity(
    response,
    findings,
    seen
) {
    for (const cookie of response.setCookies || []) {
        const firstPart = cookie.split(";")[0];
        const equalsAt = firstPart.indexOf("=");

        if (equalsAt < 1) {
            continue;
        }

        const name = firstPart
            .slice(0, equalsAt)
            .trim();

        const attrs = cookie
            .split(";")
            .slice(1)
            .map((part) => part.trim().toLowerCase());

        const module = `[cookie: ${name}]`;

        if (!attrs.some((part) => part === "httponly")) {
            addFinding(findings, seen, {
                vulnerability: "Cookie Missing HttpOnly",
                affected_module: module,
                description:
                    "An observed Set-Cookie header did not include HttpOnly.",
                observed_result:
                    `${name} was set without HttpOnly.`,
                impact:
                    "If this cookie is sensitive and script injection exists, client-side scripts may be able to read it.",
                severity: "Low",
                confidence: "High"
            });
        }

        if (!attrs.some((part) => part.startsWith("samesite="))) {
            addFinding(findings, seen, {
                vulnerability: "Cookie Missing SameSite",
                affected_module: module,
                description:
                    "An observed Set-Cookie header did not include an explicit SameSite attribute.",
                observed_result:
                    `${name} was set without an explicit SameSite attribute.`,
                impact:
                    "Cross-site request exposure may increase for authentication cookies; browser defaults and other CSRF controls also matter.",
                severity: "Low",
                confidence: "High"
            });
        }

        if (
            new URL(response.url).protocol === "https:" &&
            !attrs.some((part) => part === "secure")
        ) {
            addFinding(findings, seen, {
                vulnerability: "Cookie Missing Secure",
                affected_module: module,
                description:
                    "A cookie set over HTTPS did not include the Secure attribute.",
                observed_result:
                    `${name} was set over HTTPS without Secure.`,
                impact:
                    "The Secure attribute helps prevent the browser from sending a sensitive cookie over plaintext HTTP.",
                severity: "Low",
                confidence: "High"
            });
        }
    }
}


// =========================================================
// DIRECTORY LISTING
// =========================================================

function looksLikeDirectoryListing(body) {
    return (
        /<title[^>]*>\s*(?:index of|directory listing for)\b/i.test(body || "") ||
        /<h1[^>]*>\s*(?:index of|directory listing for)\b/i.test(body || "") ||
        (
            /parent directory/i.test(body || "") &&
            /<pre\b|<table\b/i.test(body || "")
        )
    );
}

function checkDirectoryListing(
    response,
    findings,
    seen
) {
    if (
        response.status !== 200 ||
        !looksLikeDirectoryListing(response.body)
    ) {
        return;
    }

    addFinding(findings, seen, {
        vulnerability: "Potential Directory Listing",
        affected_module: responsePath(response),
        description:
            "The response resembles a generated directory index.",
        observed_result:
            "Index-of or Parent-Directory markers were identified.",
        impact:
            "Directory listings can expose filenames, backups, and resources that should not be publicly browsable.",
        severity: "Medium",
        confidence: "Medium"
    });
}


// =========================================================
// FORM DATA HELPERS
// =========================================================

function buildFormData(
    form,
    testedParameter,
    testedValue
) {
    const data = {};

    for (const input of form.inputs) {
        const type =
            String(input.type || "text").toLowerCase();

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
        } else if (input.name === testedParameter) {
            data[input.name] = testedValue;
        } else {
            data[input.name] =
                input.value ||
                (type === "hidden" ? "" : "1");
        }
    }

    return data;
}

async function issueInputTest(
    client,
    form,
    parameter,
    value
) {
    if (form.method === "POST") {
        return postForm(
            client,
            form.action,
            buildFormData(form, parameter, value)
        );
    }

    const parsed = new URL(form.action);

    for (const input of form.inputs) {
        if (
            [
                "password",
                "file",
                "checkbox",
                "radio",
                "button",
                "reset"
            ].includes(input.type)
        ) {
            continue;
        }

        parsed.searchParams.set(
            input.name,
            input.name === parameter
                ? value
                : (input.value || "1")
        );
    }

    if (
        !form.inputs.some(
            (input) => input.name === parameter
        )
    ) {
        parsed.searchParams.set(parameter, value);
    }

    return fetchPage(
        client,
        parsed.toString()
    );
}

function isInputTestable(input) {
    return ![
        "hidden",
        "submit",
        "button",
        "reset",
        "file",
        "password",
        "checkbox",
        "radio"
    ].includes(String(input.type).toLowerCase());
}


// =========================================================
// SQL ERROR DETECTION
// =========================================================

function sqlError(body) {
    return [
        /you have an error in your sql syntax/i,
        /sql syntax.*mysql/i,
        /mysqli?_fetch/i,
        /mysqli?_query/i,
        /mysqli?_sql_exception/i,
        /sqlstate\[/i,
        /pdoexception/i,
        /warning:\s*mysql/i,
        /unclosed quotation mark/i,
        /sqlite.*error/i,
        /mariadb server version/i
    ].some((pattern) => pattern.test(body || ""));
}


// =========================================================
// CLASSIC SQL INJECTION
// =========================================================

async function testClassicSqlInjection(
    client,
    form,
    parameter,
    findings,
    seen
) {
    const payloads = [
        "'",
        '"',
        "1' OR '1'='1"
    ];

    for (const payload of payloads) {
        try {
            const response = await issueInputTest(
                client,
                form,
                parameter,
                payload
            );

            if (!sqlError(response.body)) {
                continue;
            }

            addFinding(findings, seen, {
                vulnerability: "SQL Injection",
                affected_module:
                    `${responsePath(response)} [${parameter}]`,
                description:
                    "A controlled SQL metacharacter produced a database-specific error signature.",
                observed_result:
                    `SQL error signatures were observed after testing parameter ${parameter}.`,
                impact:
                    "Depending on the query and database privileges, SQL injection may permit unauthorized record access or query manipulation.",
                severity: "High",
                confidence: "High"
            });

            return;
        } catch {
            // Keep an individual failed request from terminating the scan.
        }
    }
}


// =========================================================
// BOOLEAN-BASED BLIND SQL INJECTION
// =========================================================

async function testBlindSqlInjection(
    client,
    form,
    parameter,
    findings,
    seen
) {
    const truePayloads = [
        "1' AND '1'='1",
        "1 AND 1=1"
    ];

    const falsePayloads = [
        "1' AND '1'='2",
        "1 AND 1=2"
    ];

    const trueSignals =
        /user id exists in the database|first name:\s*|surname:\s*/i;

    const falseSignals =
        /user id is missing from the database|user id not found|does not exist/i;

    for (const truePayload of truePayloads) {
        for (const falsePayload of falsePayloads) {
            try {
                const yes = await issueInputTest(
                    client,
                    form,
                    parameter,
                    truePayload
                );

                const no = await issueInputTest(
                    client,
                    form,
                    parameter,
                    falsePayload
                );

                const yesBody = String(yes.body || "");
                const noBody = String(no.body || "");

                const pairedSignals =
                    trueSignals.test(yesBody) &&
                    falseSignals.test(noBody);

                const oppositeSignals =
                    falseSignals.test(yesBody) &&
                    trueSignals.test(noBody);

                if (!pairedSignals && !oppositeSignals) {
                    continue;
                }

                addFinding(findings, seen, {
                    vulnerability: "SQL Injection (Blind)",
                    affected_module:
                        `${responsePath(yes)} [${parameter}]`,
                    description:
                        "Paired true/false SQL conditions produced distinct application responses consistent with boolean-based SQL injection.",
                    observed_result:
                        "The response to the true condition differed from the false condition using DVWA-style database-result messages.",
                    impact:
                        "Boolean-based SQL injection can permit inference of database information even when SQL errors are not displayed.",
                    severity: "High",
                    confidence: "High"
                });

                return;
            } catch {
                // Continue with the next controlled comparison.
            }
        }
    }
}


// =========================================================
// REFLECTED HTML INJECTION / POTENTIAL XSS
// Uses inert markup. JavaScript is not executed.
// =========================================================

async function testReflectedXss(
    client,
    form,
    parameter,
    findings,
    seen
) {
    const marker =
        `VAPT_XSS_${Math.random().toString(36).slice(2, 10)}`;

    const payload =
        `"><vapt-probe data-marker="${marker}">probe</vapt-probe>`;

    try {
        const response = await issueInputTest(
            client,
            form,
            parameter,
            payload
        );

        const body = String(response.body || "");

        const rawTag = new RegExp(
            `<vapt-probe\\s+data-marker=["']${marker}["']`,
            "i"
        ).test(body);

        if (!rawTag) {
            return;
        }

        addFinding(findings, seen, {
            vulnerability:
                "Reflected HTML Injection (Potential XSS)",
            affected_module:
                `${responsePath(response)} [${parameter}]`,
            description:
                "An inert HTML probe was reflected as raw markup rather than encoded text. This indicates an unsafe HTML context; JavaScript execution was not tested.",
            observed_result:
                `The unescaped <vapt-probe> tag with marker ${marker} appeared in the response.`,
            impact:
                "If attacker-controlled markup can reach an executable context, it may enable client-side injection. Browser-context validation is required before confirming XSS.",
            severity: "Medium",
            confidence: "High"
        });
    } catch {
        // Continue scanning.
    }
}


// =========================================================
// CSRF FORM ANALYSIS
// Never submit the password-change form.
// =========================================================

function hasAntiCsrfToken(form) {
    return form.inputs.some((input) => {
        if (input.type !== "hidden") {
            return false;
        }

        const name = String(
            input.name || ""
        ).toLowerCase();

        return /(csrf|xsrf|nonce|anti.?forgery)/i.test(name);
    });
}

function checkCsrfForm(
    form,
    findings,
    seen
) {
    const path = new URL(form.action)
        .pathname
        .toLowerCase();

    if (!path.includes("/vulnerabilities/csrf/")) {
        return;
    }

    const names = form.inputs.map(
        (input) => String(input.name).toLowerCase()
    );

    const passwordChange =
        names.includes("password_new") &&
        names.includes("password_conf");

    if (
        !passwordChange ||
        hasAntiCsrfToken(form)
    ) {
        return;
    }

    addFinding(findings, seen, {
        vulnerability:
            "CSRF - Password Change Form Without Token",
        affected_module: path,
        description:
            "The password-change form has no recognizable hidden anti-CSRF token. The scanner does not submit the form or change the password.",
        observed_result:
            "The form contains password_new and password_conf fields but no recognizable anti-CSRF token.",
        impact:
            "A cross-site request may be able to trigger an unwanted password change if no effective referer, SameSite, or other CSRF defense applies.",
        severity: "High",
        confidence: "Medium"
    });
}


// =========================================================
// POTENTIAL DOM XSS
// Static inspection only; not confirmed execution.
// =========================================================

function testDomXssSource(
    html,
    pageUrl,
    findings,
    seen
) {
    if (
        !new URL(pageUrl).pathname
            .toLowerCase()
            .includes("/vulnerabilities/xss_d/")
    ) {
        return;
    }

    const source =
        /(?:document\.location|window\.location|location\.(?:hash|search|href)|document\.URL)/i
            .test(html || "");

    const sink =
        /(?:document\.write\s*\(|(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|eval\s*\()/i
            .test(html || "");

    if (!source || !sink) {
        return;
    }

    addFinding(findings, seen, {
        vulnerability: "Potential DOM-Based XSS",
        affected_module: new URL(pageUrl).pathname,
        description:
            "The DOM XSS module response contains both location-derived data sources and a potentially unsafe DOM/script sink. Static response inspection cannot fully prove runtime exploitability.",
        observed_result:
            "Location/document URL source patterns and document.write/HTML-insertion/eval sink patterns co-occurred in the module response.",
        impact:
            "If attacker-controlled URL data reaches the sink without appropriate encoding, client-side script injection may be possible.",
        severity: "Medium",
        confidence: "Medium"
    });
}


// =========================================================
// COMMAND INJECTION
// Restricted to DVWA's exec module and the ip parameter.
// Echo probes are used; no files or account data are altered.
// =========================================================

async function testCommandInjection(
    client,
    form,
    parameter,
    findings,
    seen
) {
    if (
        !new URL(form.action).pathname
            .toLowerCase()
            .includes("/vulnerabilities/exec/")
    ) {
        return;
    }

    if (String(parameter).toLowerCase() !== "ip") {
        return;
    }

    const marker =
        `VAPT_CMDI_${Math.random().toString(36).slice(2, 10)}`;

    const payloads = [
        `127.0.0.1; echo ${marker}`,
        `127.0.0.1 && echo ${marker}`,
        `127.0.0.1 & echo ${marker}`
    ];

    for (const payload of payloads) {
        try {
            const response = await issueInputTest(
                client,
                form,
                parameter,
                payload
            );

            const body = String(response.body || "");

            // Remove input controls to avoid treating input-field
            // reflection as command output.
            const visibleBody = body.replace(
                /<input\b[^>]*>/gi,
                " "
            );

            if (
                !visibleBody.includes(marker) ||
                visibleBody.toLowerCase().includes(
                    `echo ${marker}`.toLowerCase()
                )
            ) {
                continue;
            }

            addFinding(findings, seen, {
                vulnerability: "Command Injection",
                affected_module:
                    `${responsePath(response)} [${parameter}]`,
                description:
                    "A unique echo marker appeared in the command-injection module response outside form controls after a controlled command-separator probe.",
                observed_result:
                    `The marker ${marker} was returned after testing the ${parameter} parameter.`,
                impact:
                    "If confirmed, command injection may permit operating-system commands to execute with the web server's privileges.",
                severity: "High",
                confidence: "High"
            });

            return;
        } catch {
            // A rejected payload is not evidence of a vulnerability.
        }
    }
}


// =========================================================
// FILE INCLUSION / PATH TRAVERSAL
// Read-only probes, restricted to DVWA's FI module.
// =========================================================

async function testFileInclusion(
    client,
    form,
    parameter,
    findings,
    seen
) {
    if (
        !new URL(form.action).pathname
            .toLowerCase()
            .includes("/vulnerabilities/fi/")
    ) {
        return;
    }

    if (String(parameter).toLowerCase() !== "page") {
        return;
    }

    const probes = [
        {
            value: "../../../../../../etc/passwd",
            pattern: /root:[^\n:]*:0:0:/
        },
        {
            value: "../../../../../../windows/win.ini",
            pattern: /^\s*\[(?:fonts|extensions)\]/im
        }
    ];

    for (const probe of probes) {
        try {
            const response = await issueInputTest(
                client,
                form,
                parameter,
                probe.value
            );

            if (
                !probe.pattern.test(
                    String(response.body || "")
                )
            ) {
                continue;
            }

            addFinding(findings, seen, {
                vulnerability:
                    "File Inclusion / Path Traversal",
                affected_module:
                    `${responsePath(response)} [${parameter}]`,
                description:
                    "A read-only traversal probe returned recognizable local system-file content.",
                observed_result:
                    `The response matched a known signature for the file probed via parameter ${parameter}.`,
                impact:
                    "Local file read can expose OS files, application configuration, and secrets.",
                severity: "High",
                confidence: "High"
            });

            return;
        } catch {
            // Try the next local-file signature.
        }
    }
}


// =========================================================
// OPEN REDIRECT
// The external destination is never followed.
// =========================================================

async function testOpenRedirect(
    client,
    value,
    parameter,
    findings,
    seen
) {
    const markerUrl =
        "https://example.invalid/vapt-redirect-check";

    const parsed = new URL(value);

    parsed.searchParams.set(parameter, markerUrl);

    try {
        const response = await client.request(
            parsed.toString(),
            {
                method: "GET",
                inspectRedirect: true
            }
        );

        if (
            ![301, 302, 303, 307, 308].includes(
                Number(response.status)
            ) ||
            !response.location
        ) {
            return;
        }

        const location = new URL(
            response.location,
            response.url
        );

        if (location.origin !== "https://example.invalid") {
            return;
        }

        addFinding(findings, seen, {
            vulnerability: "Open Redirect",
            affected_module:
                `${responsePath(response)} [${parameter}]`,
            description:
                "The DVWA redirect module returned an HTTP redirect to a controlled external test URL. The scanner did not follow that destination.",
            observed_result:
                `HTTP ${response.status} redirected to ${location.origin}${location.pathname}.`,
            impact:
                "Unvalidated redirects can facilitate phishing and allow attackers to abuse application trust.",
            severity: "Medium",
            confidence: "High"
        });
    } catch {
        // External redirect destinations are intentionally never followed.
    }
}


// =========================================================
// WEAK SESSION ID CHECK
// Generates two DVWA test cookies; no account data is changed.
// =========================================================

function getCookieValue(
    setCookies,
    cookieName
) {
    const found = (setCookies || []).find(
        (cookie) =>
            new RegExp(
                `^\\s*${cookieName}=`,
                "i"
            ).test(cookie)
    );

    if (!found) {
        return null;
    }

    const first = found.split(";")[0];

    return first.slice(
        first.indexOf("=") + 1
    ).trim();
}

async function testWeakSessionIds(
    client,
    rootUrl,
    findings,
    seen
) {
    const pageUrl = new URL(
        "vulnerabilities/weak_id/",
        rootUrl
    ).toString();

    let page;

    try {
        page = await fetchPage(client, pageUrl);
    } catch {
        return;
    }

    if (!/weak session ids/i.test(page.body || "")) {
        return;
    }

    const forms = discoverForms(
        page.body,
        page.url,
        rootUrl
    );

    let form = forms.find(
        (item) =>
            new URL(item.action).pathname
                .toLowerCase()
                .includes("/vulnerabilities/weak_id/")
    );

    if (!form) {
        form = {
            action: pageUrl,
            method: "POST",
            inputs: [
                {
                    name: "generate",
                    type: "submit",
                    value: "Generate"
                }
            ]
        };
    }

    async function generate() {
        try {
            const data = buildFormData(
                form,
                "",
                ""
            );

            if (!Object.keys(data).length) {
                data.generate = "Generate";
            }

            const response = await postForm(
                client,
                form.action,
                data
            );

            return getCookieValue(
                response.setCookies,
                "dvwaSession"
            );
        } catch {
            return null;
        }
    }

    const first = await generate();
    const second = await generate();

    if (
        first == null ||
        second == null ||
        !/^\d{1,12}$/.test(first) ||
        !/^\d{1,12}$/.test(second)
    ) {
        return;
    }

    const a = Number(first);
    const b = Number(second);

    const sequential =
        b === a + 1 ||
        a === b + 1;

    const timeLike =
        first.length === 10 &&
        second.length === 10 &&
        Math.abs(b - a) <= 2;

    if (!sequential && !timeLike) {
        return;
    }

    addFinding(findings, seen, {
        vulnerability: "Weak Session ID",
        affected_module: new URL(pageUrl).pathname,
        description:
            "Two generated dvwaSession values were small sequential or time-like numeric values in DVWA's weak-session-ID module.",
        observed_result:
            `Observed dvwaSession values: ${first} and ${second}.`,
        impact:
            "Predictable session identifiers may make guessing or session fixation easier, depending on how the identifier is used.",
        severity: sequential ? "High" : "Medium",
        confidence: sequential ? "High" : "Medium"
    });
}


// =========================================================
// UPLOAD ATTACK-SURFACE INSPECTION
// Does not upload a file or claim server-side validation is absent.
// =========================================================

function checkUploadForm(
    form,
    findings,
    seen
) {
    const path = new URL(form.action)
        .pathname
        .toLowerCase();

    if (!path.includes("/vulnerabilities/upload/")) {
        return;
    }

    const fileInput = form.inputs.find(
        (input) => input.type === "file"
    );

    if (!fileInput) {
        return;
    }

    const accept = fileInput.accept || "";

    addFinding(findings, seen, {
        vulnerability: "File Upload Attack Surface Detected",
        affected_module: path,
        description:
            "The page exposes a file-upload control. The scanner does not submit a file; server-side type, content, storage, and execution controls require dedicated validation.",
        observed_result:
            `File input '${fileInput.name}' was present` +
            (
                accept
                    ? ` with accept='${accept}'`
                    : " without a browser-side accept filter"
            ) +
            ".",
        impact:
            "Unsafe upload handling can enable storage abuse, path traversal, or code execution if server-side checks and storage isolation are inadequate.",
        severity: "Info",
        confidence: "High"
    });
}


// =========================================================
// STORED XSS ATTACK-SURFACE INSPECTION
// Does not write a persistent guestbook entry.
// =========================================================

function checkStoredXssSurface(
    form,
    findings,
    seen
) {
    const path = new URL(form.action)
        .pathname
        .toLowerCase();

    if (!path.includes("/vulnerabilities/xss_s/")) {
        return;
    }

    const hasMessage = form.inputs.some(
        (input) =>
            /message|mtxmessage/i.test(input.name)
    );

    if (!hasMessage) {
        return;
    }

    addFinding(findings, seen, {
        vulnerability:
            "Stored XSS Input Surface Requires Validation",
        affected_module: path,
        description:
            "A persistent message input was discovered. The scanner did not submit a payload, so this is not a confirmed stored-XSS vulnerability.",
        observed_result:
            "A message-like input was present on the stored-XSS module.",
        impact:
            "If stored content is rendered without contextual output encoding, it may create persistent client-side injection risk.",
        severity: "Info",
        confidence: "High"
    });
}


// =========================================================
// CHECK RESPONSE FOR DIRECTORY LISTING
// =========================================================

function checkDirectoryAndSourceIssues(
    response,
    findings,
    seen
) {
    if (
        response.status === 200 &&
        looksLikeDirectoryListing(response.body)
    ) {
        checkDirectoryListing(
            response,
            findings,
            seen
        );
    }
}


// =========================================================
// CHECK SENSITIVE FILES
// All requests remain within the local DVWA root.
// =========================================================

async function checkSensitiveFiles(
    client,
    rootUrl,
    findings,
    seen
) {
    const probes = [
        {
            path: ".git/HEAD",
            title: "Exposed Git Metadata",
            signature: /ref:\s*refs\/(?:heads|remotes)\//i,
            severity: "Medium"
        },
        {
            path: ".env",
            title: "Potential Environment File Exposure",
            signature: /(?:DB_PASSWORD|DATABASE_URL|APP_KEY|SECRET_KEY)\s*=/i,
            severity: "High"
        },
        {
            path: "config/config.inc.php.bak",
            title: "Potential Backup Configuration Exposure",
            signature: /(?:db_password|db_user|db_database|\$_DVWA)/i,
            severity: "High"
        },
        {
            path: "config/config.inc.php~",
            title: "Potential Backup Configuration Exposure",
            signature: /(?:db_password|db_user|db_database|\$_DVWA)/i,
            severity: "High"
        },
        {
            path: "backup.zip",
            title: "Potential Backup Archive Exposure",
            signature: null,
            severity: "Medium"
        },
        {
            path: "phpinfo.php",
            title: "PHP Information Page Exposure",
            signature: /phpinfo\(\)|PHP Version\s+\d+\.\d+/i,
            severity: "Medium"
        }
    ];

    for (const probe of probes) {
        const url = new URL(
            probe.path,
            rootUrl
        ).toString();

        try {
            const response = await fetchPage(
                client,
                url
            );

            if (response.status !== 200) {
                continue;
            }

            const body = String(response.body || "");

            // A generic application response with status 200 is not
            // enough: a specific sensitive-file signature must match.
            let matched = probe.signature
                ? probe.signature.test(body)
                : false;

            if (probe.path === "backup.zip") {
                matched =
                    String(response.headers["content-type"] || "")
                        .toLowerCase()
                        .includes("zip") ||
                    body.startsWith("PK\u0003\u0004");
            }

            if (!matched) {
                continue;
            }

            addFinding(findings, seen, {
                vulnerability: probe.title,
                affected_module: `/${probe.path}`,
                description:
                    `A scoped check for ${probe.path} returned content matching a known sensitive-file signature.`,
                observed_result:
                    `The path ${probe.path} responded with status 200 and a matching signature.`,
                impact:
                    "Exposed configuration, version-control metadata, or backups can reveal source code and secrets.",
                severity: probe.severity,
                confidence: "High"
            });
        } catch {
            // File absent or inaccessible; continue.
        }
    }
}


// =========================================================
// ROUTE-SPECIFIC FORM TESTS
// =========================================================

async function testModuleForm(
    client,
    form,
    findings,
    seen
) {
    const path = new URL(form.action)
        .pathname
        .toLowerCase();

    const module = moduleNameFromPath(path);

    checkCsrfForm(form, findings, seen);
    checkUploadForm(form, findings, seen);
    checkStoredXssSurface(form, findings, seen);

    // SQL injection
    if (["sqli", "sqli_blind"].includes(module)) {
        const candidates = form.inputs.filter(
            (input) =>
                isInputTestable(input) &&
                /^(id|user_id|account|name|title)$/i.test(
                    input.name
                )
        );

        for (const input of candidates) {
            if (module === "sqli") {
                await testClassicSqlInjection(
                    client,
                    form,
                    input.name,
                    findings,
                    seen
                );
            }

            if (module === "sqli_blind") {
                await testClassicSqlInjection(
                    client,
                    form,
                    input.name,
                    findings,
                    seen
                );

                await testBlindSqlInjection(
                    client,
                    form,
                    input.name,
                    findings,
                    seen
                );
            }
        }
    }

    // Reflected HTML injection
    if (module === "xss_r") {
        for (const input of form.inputs.filter(isInputTestable)) {
            await testReflectedXss(
                client,
                form,
                input.name,
                findings,
                seen
            );
        }
    }

    // Command injection
    if (module === "exec") {
        for (const input of form.inputs.filter(
            (item) =>
                isInputTestable(item) &&
                /^ip$/i.test(item.name)
        )) {
            await testCommandInjection(
                client,
                form,
                input.name,
                findings,
                seen
            );
        }
    }

    // File inclusion
    if (module === "fi") {
        for (const input of form.inputs.filter(
            (item) =>
                isInputTestable(item) &&
                /^page$/i.test(item.name)
        )) {
            await testFileInclusion(
                client,
                form,
                input.name,
                findings,
                seen
            );
        }
    }
}


// =========================================================
// QUERY-PARAMETER TESTS
// =========================================================

async function testQueryParams(
    client,
    response,
    rootUrl,
    findings,
    seen
) {
    const url = new URL(response.url);
    const module = moduleNameFromPath(url.pathname);

    // Reflected XSS
    if (module === "xss_r") {
        for (const param of url.searchParams.keys()) {
            const form = {
                action: response.url,
                method: "GET",
                inputs: [
                    {
                        name: param,
                        type: "text",
                        value:
                            url.searchParams.get(param) || "1"
                    }
                ]
            };

            await testReflectedXss(
                client,
                form,
                param,
                findings,
                seen
            );
        }
    }

    // SQL injection and blind SQL injection
    if (
        module === "sqli" ||
        module === "sqli_blind"
    ) {
        for (const param of url.searchParams.keys()) {
            const form = {
                action: response.url,
                method: "GET",
                inputs: [
                    {
                        name: param,
                        type: "text",
                        value:
                            url.searchParams.get(param) || "1"
                    }
                ]
            };

            if (module === "sqli") {
                await testClassicSqlInjection(
                    client,
                    form,
                    param,
                    findings,
                    seen
                );
            } else {
                await testClassicSqlInjection(
                    client,
                    form,
                    param,
                    findings,
                    seen
                );

                await testBlindSqlInjection(
                    client,
                    form,
                    param,
                    findings,
                    seen
                );
            }
        }
    }

    // File inclusion
    if (
        module === "fi" &&
        url.searchParams.has("page")
    ) {
        const form = {
            action: response.url,
            method: "GET",
            inputs: [
                {
                    name: "page",
                    type: "text",
                    value:
                        url.searchParams.get("page") ||
                        "include.php"
                }
            ]
        };

        await testFileInclusion(
            client,
            form,
            "page",
            findings,
            seen
        );
    }

    // Open redirect
    if (module === "open_redirect") {
        const param = url.searchParams.has("redirect")
            ? "redirect"
            : null;

        if (param) {
            await testOpenRedirect(
                client,
                response.url,
                param,
                findings,
                seen
            );
        }
    }
}

// =========================================================
// EXTRACT DVWA LOGIN TOKEN
// =========================================================

function extractUserToken(html) {
    const inputRegex = /<input\b([^>]*)>/gi;

    let match;

    while ((match = inputRegex.exec(html || "")) !== null) {
        const attributes = match[1] || "";

        const name = getAttribute(
            attributes,
            "name"
        );

        if (name === "user_token") {
            return getAttribute(
                attributes,
                "value"
            ) || null;
        }
    }

    return null;
}


// =========================================================
// DVWA LOGIN
// Authenticates the scanner and verifies the requested
// security level before vulnerability testing begins.
// =========================================================

async function loginToDvwa(
    client,
    targetUrl,
    requestedSecurityLevel = "low"
) {
    const baseUrl = getDvwaBaseUrl(targetUrl);

    const allowedLevels = [
        "low",
        "medium",
        "high",
        "impossible"
    ];

    const securityLevel = String(
        requestedSecurityLevel || "low"
    ).trim().toLowerCase();

    if (!allowedLevels.includes(securityLevel)) {
        throw new Error(
            "Invalid DVWA security level. " +
            "Choose low, medium, high, or impossible."
        );
    }

    const loginUrl = new URL(
        "login.php",
        baseUrl
    ).toString();

    // Step 1: Open the login page and retrieve its CSRF token.
    const loginPage = await fetchPage(
        client,
        loginUrl
    );

    const token = extractUserToken(
        loginPage.body
    );

    if (!token) {
        throw new Error(
            "DVWA login token was not found. " +
            "Check that DVWA is running and the target URL is correct."
        );
    }

    // Step 2: Read credentials from backend/.env.
    const username =
        process.env.DVWA_USERNAME || "admin";

    const password =
        process.env.DVWA_PASSWORD || "password";

    // Step 3: Submit the login form.
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

    // Step 4: Confirm that login succeeded.
    const loginBody = String(
        loginResponse.body || ""
    );

    if (
        /<input\b[^>]*\bname\s*=\s*["']username["']/i.test(
            loginBody
        ) &&
        /\bDVWA\b/i.test(loginBody) &&
        /\bLogin\b/i.test(loginBody)
    ) {
        throw new Error(
            "DVWA login failed. Check DVWA_USERNAME and " +
            "DVWA_PASSWORD in backend/.env."
        );
    }

    // Step 5: Set the security cookie in the scanner's own
    // authenticated session. This is independent of your browser.
    client.setCookie(
        "security",
        securityLevel
    );

    // Step 6: Verify access to the authenticated dashboard.
    const dashboard = await fetchPage(
        client,
        new URL("index.php", baseUrl).toString()
    );

    if (
        !/logout/i.test(dashboard.body || "") &&
        !/security level/i.test(dashboard.body || "")
    ) {
        throw new Error(
            "DVWA authentication could not be verified after login."
        );
    }

    // Step 7: Ask DVWA which security level is currently active.
    const securityPage = await fetchPage(
        client,
        new URL("security.php", baseUrl).toString()
    );

    // Strip HTML tags so this also works if DVWA changes whitespace
    // or the formatting around the <em> element.
    const visibleSecurityText = String(
        securityPage.body || ""
    )
        .replace(/<[^>]*>/g, " ")
        .replace(/\s+/g, " ");

    const levelMatch = visibleSecurityText.match(
        /security level is currently:\s*(low|medium|high|impossible)\b/i
    );

    if (!levelMatch) {
        throw new Error(
            "Could not verify the active DVWA security level. " +
            "The scan was stopped to avoid recording an unverified level."
        );
    }

    const actualSecurityLevel =
        levelMatch[1].toLowerCase();

    if (actualSecurityLevel !== securityLevel) {
        throw new Error(
            `DVWA security-level mismatch. Requested: ${securityLevel}; ` +
            `DVWA reported: ${actualSecurityLevel}.`
        );
    }

    return {
        loginUrl,
        username,
        securityLevel: actualSecurityLevel,
        securityLevelVerified: true,

        defaultCredentialsUsed:
            username === "admin" &&
            password === "password"
    };
}

// =========================================================
// MAIN SCANNER
// =========================================================

async function scanTarget(
    targetUrl,
    options = {}
) {
    const requestedSecurityLevel = String(
        options.securityLevel ??
        process.env.DVWA_SECURITY_LEVEL ??
        "low"
    ).trim().toLowerCase();

    if (!SECURITY_LEVELS.includes(requestedSecurityLevel)) {
        throw new Error(
            "Invalid DVWA security level. Choose low, medium, high, or impossible."
        );
    }

    const startedAt = Date.now();

    const target = assertDvwaRoot(targetUrl);
    const rootUrl = target.toString();

    const client = new SessionClient(rootUrl);

    // Authenticate and verify the level before any vulnerability tests.
    const authentication = await loginToDvwa(
        client,
        rootUrl,
        requestedSecurityLevel
    );

    const securityLevel =
        authentication.securityLevel;

    const findings = [];
    const seen = new Set();
    const pages = [];
    const queue = [];
    const discovered = new Set();
    const testedFormKeys = new Set();

    let htmlPagesScanned = 0;
    let formsDiscovered = 0;
    let parametersTested = 0;

    // -----------------------------------------------------
    // QUEUE HELPER
    // -----------------------------------------------------

    function enqueue(value) {
        const normalized = normalizeUrl(
            value,
            rootUrl
        );

        if (
            !normalized ||
            !isWithinDvwaScope(normalized, rootUrl)
        ) {
            return;
        }

        const parsed = new URL(normalized);

        if (STATIC_EXTENSIONS.test(parsed.pathname)) {
            return;
        }

        if (
            BLOCKED_PATHS.some(
                (part) =>
                    parsed.pathname
                        .toLowerCase()
                        .includes(part)
            )
        ) {
            return;
        }

        if (
            discovered.has(normalized) ||
            discovered.size >= MAX_RESOURCES
        ) {
            return;
        }

        discovered.add(normalized);
        queue.push(normalized);
    }

    // -----------------------------------------------------
    // SEED THE CRAWLER
    // This is the major coverage improvement: important DVWA
    // modules are visited even if the page link is missed.
    // -----------------------------------------------------

    enqueue(rootUrl);

    enqueue(
        new URL("index.php", rootUrl).toString()
    );

    for (const modulePath of DVWA_MODULES) {
        enqueue(
            new URL(modulePath, rootUrl).toString()
        );
    }

    // -----------------------------------------------------
    // CRAWL AND TEST
    // -----------------------------------------------------

    while (
        queue.length &&
        pages.length < MAX_RESOURCES
    ) {
        const current = queue.shift();

        try {
            const response = await fetchPage(
                client,
                current
            );

            pages.push({
                url: response.url,
                status: response.status
            });

            checkSecurityHeaders(
                response,
                findings,
                seen
            );

            checkCookieSecurity(
                response,
                findings,
                seen
            );

            checkDirectoryAndSourceIssues(
                response,
                findings,
                seen
            );

            if (response.status >= 400) {
                continue;
            }

            if (!isLikelyHtml(response)) {
                continue;
            }

            htmlPagesScanned += 1;

            // DOM XSS is reported as a potential issue only.
            testDomXssSource(
                response.body,
                response.url,
                findings,
                seen
            );

            // Discover additional navigation links.
            const links = discoverLinks(
                response.body,
                response.url,
                rootUrl
            );

            for (const link of links) {
                enqueue(link);
            }

            // Discover forms.
            const forms = discoverForms(
                response.body,
                response.url,
                rootUrl
            );

            for (const form of forms) {
                const formKey = [
                    form.method,
                    form.action,
                    form.inputs
                        .map(
                            (item) =>
                                `${item.name}:${item.type}`
                        )
                        .join(",")
                ].join("|");

                if (testedFormKeys.has(formKey)) {
                    continue;
                }

                testedFormKeys.add(formKey);
                formsDiscovered += 1;

                checkCsrfForm(
                    form,
                    findings,
                    seen
                );

                checkUploadForm(
                    form,
                    findings,
                    seen
                );

                checkStoredXssSurface(
                    form,
                    findings,
                    seen
                );

                const module = moduleNameFromPath(
                    new URL(form.action).pathname
                );

                const relevantModules = [
                    "sqli",
                    "sqli_blind",
                    "xss_r",
                    "exec",
                    "fi"
                ];

                if (!relevantModules.includes(module)) {
                    continue;
                }

                parametersTested += form.inputs
                    .filter(isInputTestable)
                    .length;

                await testModuleForm(
                    client,
                    form,
                    findings,
                    seen
                );
            }

            // Test parameters already present in page URLs.
            await testQueryParams(
                client,
                response,
                rootUrl,
                findings,
                seen
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

    // -----------------------------------------------------
    // CHECK COMMON SENSITIVE FILE LOCATIONS
    // -----------------------------------------------------

    await checkSensitiveFiles(
        client,
        rootUrl,
        findings,
        seen
    );

    // -----------------------------------------------------
    // WEAK SESSION ID TEST
    // Two benign requests generate the module's test cookies.
    // -----------------------------------------------------

    await testWeakSessionIds(
        client,
        rootUrl,
        findings,
        seen
    );

    // -----------------------------------------------------
    // DEFAULT CREDENTIALS
    // Only report if the login actually succeeded using the
    // default username/password combination.
    // -----------------------------------------------------

    if (authentication.defaultCredentialsUsed) {
        addFinding(findings, seen, {
            vulnerability: "Default DVWA Credentials Accepted",
            affected_module: "/login.php",
            description:
                "The scanner authenticated successfully using the default DVWA admin/password credentials. Confirm whether these credentials remain enabled intentionally in this lab.",
            observed_result:
                "The configured default credentials admin/password were accepted by the local DVWA login page.",
            impact:
                "Default credentials on a non-isolated deployment can allow unauthorized administrative access.",
            severity: "High",
            confidence: "High"
        });
    }

    // -----------------------------------------------------
    // FINAL RESPONSE
    // Retains the expected scanner result structure.
    // -----------------------------------------------------

    return {
        target_url: rootUrl,

        authenticated: true,

        authentication,

        security_level: securityLevel,

        pages_scanned: pages.length,

        html_pages_scanned: htmlPagesScanned,

        javascript_files_scanned: 0,

        api_endpoints_discovered: 0,

        forms_discovered: formsDiscovered,

        parameters_tested: parametersTested,

        duration_ms: Date.now() - startedAt,

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