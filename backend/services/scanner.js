const { URL } = require("url");

const MAX_PAGES = 40;
const MAX_FORMS = 60;
const REQUEST_TIMEOUT = 8000;
const MAX_BODY = 800000;

// =========================================================
// SESSION CLIENT
// Keeps cookies between requests.
// This is required for authenticated DVWA scanning.
// =========================================================

class SessionClient {
    constructor() {
        this.cookies = new Map();
    }

    setCookie(name, value) {
        this.cookies.set(name, value);
    }

    updateCookies(response) {
        let setCookies = [];

        if (
            response.headers &&
            typeof response.headers.getSetCookie === "function"
        ) {
            setCookies =
                response.headers.getSetCookie();
        } else {
            const single =
                response.headers.get("set-cookie");

            if (single) {
                setCookies = [single];
            }
        }

        for (const cookie of setCookies) {
            const firstPart =
                cookie.split(";")[0];

            const separator =
                firstPart.indexOf("=");

            if (separator === -1) {
                continue;
            }

            const name =
                firstPart
                    .slice(0, separator)
                    .trim();

            const value =
                firstPart
                    .slice(separator + 1)
                    .trim();

            if (name) {
                this.cookies.set(
                    name,
                    value
                );
            }
        }
    }

    getCookieHeader() {
        return Array.from(
            this.cookies.entries()
        )
            .map(
                ([name, value]) =>
                    `${name}=${value}`
            )
            .join("; ");
    }

    async request(
        url,
        options = {},
        redirectCount = 0
    ) {
        if (redirectCount > 5) {
            throw new Error(
                "Too many redirects."
            );
        }

        const controller =
            new AbortController();

        const timer =
            setTimeout(
                () => {
                    controller.abort();
                },
                REQUEST_TIMEOUT
            );

        try {
            const headers = {
                "User-Agent":
                    "VAPT-Scanner/1.0 (authorized-lab)",

                "Accept":
                    "text/html,application/xhtml+xml,*/*",

                ...(options.headers || {})
            };

            const cookieHeader =
                this.getCookieHeader();

            if (cookieHeader) {
                headers.Cookie =
                    cookieHeader;
            }

            const response =
                await fetch(
                    url,
                    {
                        ...options,

                        headers,

                        redirect:
                            "manual",

                        signal:
                            controller.signal
                    }
                );

            this.updateCookies(
                response
            );

            // -------------------------------------------------
            // HANDLE REDIRECTS
            // -------------------------------------------------

            if (
                response.status >= 300 &&
                response.status < 400
            ) {
                const location =
                    response.headers.get(
                        "location"
                    );

                if (location) {
                    const nextUrl =
                        new URL(
                            location,
                            url
                        ).toString();

                    const nextOptions = {
                        ...options
                    };

                    // Browser-like behavior:
                    // after a 301/302/303 redirect,
                    // turn POST into GET.
                    if (
                        response.status === 301 ||
                        response.status === 302 ||
                        response.status === 303
                    ) {
                        nextOptions.method =
                            "GET";

                        delete nextOptions.body;
                    }

                    return this.request(
                        nextUrl,
                        nextOptions,
                        redirectCount + 1
                    );
                }
            }

            const body =
                await response.text();

            return {
                url:
                    response.url || url,

                status:
                    response.status,

                headers:
                    Object.fromEntries(
                        response.headers.entries()
                    ),

                body:
                    body.slice(
                        0,
                        MAX_BODY
                    )
            };

        } finally {
            clearTimeout(timer);
        }
    }
}


// =========================================================
// HTTP HELPERS
// =========================================================

async function fetchPage(
    client,
    url
) {
    return client.request(
        url,
        {
            method:
                "GET"
        }
    );
}


async function postForm(
    client,
    url,
    data
) {
    const body =
        new URLSearchParams();

    for (
        const [key, value]
        of Object.entries(data)
    ) {
        body.append(
            key,
            value == null
                ? ""
                : String(value)
        );
    }

    return client.request(
        url,
        {
            method:
                "POST",

            headers: {
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },

            body:
                body.toString()
        }
    );
}


// =========================================================
// URL NORMALIZATION
// =========================================================

function normalizeUrl(
    value,
    base
) {
    try {
        const url =
            new URL(
                value,
                base
            );

        url.hash = "";

        return url.toString();

    } catch {
        return null;
    }
}


// =========================================================
// SAME HOST CHECK
// =========================================================

function sameHost(
    first,
    second
) {
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
// DISCOVER LINKS
// =========================================================

function discoverLinks(
    html,
    baseUrl
) {
    const links =
        new Set();

    const regex =
        /(?:href|action)\s*=\s*["']([^"'#]+)["']/gi;

    let match;

    while (
        (match = regex.exec(html)) !== null
    ) {
        const url =
            normalizeUrl(
                match[1],
                baseUrl
            );

        if (
            url &&
            sameHost(
                url,
                baseUrl
            )
        ) {
            links.add(url);
        }
    }

    return Array.from(
        links
    );
}


// =========================================================
// SHOULD CRAWL URL?
// Avoid destructive/admin actions.
// =========================================================

function shouldCrawl(
    url
) {
    try {
        const pathname =
            new URL(url)
                .pathname
                .toLowerCase();

        const blocked = [
            "/logout.php",
            "/setup.php",
            "/phpinfo.php",
            "/view_source.php",
            "/view_source_all.php"
        ];

        return !blocked.some(
            (item) =>
                pathname.includes(item)
        );

    } catch {
        return false;
    }
}


// =========================================================
// SHOULD TEST FORM?
// Avoid forms that change state or perform
// destructive operations.
// =========================================================

function shouldTestForm(
    action
) {
    try {
        const pathname =
            new URL(action)
                .pathname
                .toLowerCase();

        const blocked = [
            "/logout.php",
            "/setup.php",
            "/security.php",
            "/csrf/",
            "/upload/"
        ];

        return !blocked.some(
            (item) =>
                pathname.includes(item)
        );

    } catch {
        return false;
    }
}


// =========================================================
// GET ATTRIBUTE
// =========================================================

function getAttribute(
    attributes,
    name
) {
    const regex =
        new RegExp(
            `${name}\\s*=\\s*["']([^"']*)["']`,
            "i"
        );

    const match =
        attributes.match(
            regex
        );

    return match
        ? match[1]
        : "";
}


// =========================================================
// DISCOVER FORMS
// =========================================================

function discoverForms(
    html,
    baseUrl
) {
    const forms = [];

    const formRegex =
        /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;

    let match;

    while (
        (match = formRegex.exec(html)) !== null
    ) {
        const attributes =
            match[1] || "";

        const formBody =
            match[2] || "";

        const actionValue =
            getAttribute(
                attributes,
                "action"
            );

        const methodValue =
            getAttribute(
                attributes,
                "method"
            );

        const action =
            normalizeUrl(
                actionValue || baseUrl,
                baseUrl
            );

        if (!action) {
            continue;
        }

        if (
            !sameHost(
                action,
                baseUrl
            )
        ) {
            continue;
        }

        if (
            !shouldTestForm(
                action
            )
        ) {
            continue;
        }

        const inputs = [];

        // -------------------------------------------------
        // INPUT ELEMENTS
        // -------------------------------------------------

        const inputRegex =
            /<input\b([^>]*)>/gi;

        let inputMatch;

        while (
            (inputMatch =
                inputRegex.exec(
                    formBody
                )) !== null
        ) {
            const inputAttributes =
                inputMatch[1] || "";

            const name =
                getAttribute(
                    inputAttributes,
                    "name"
                );

            if (!name) {
                continue;
            }

            const type =
                (
                    getAttribute(
                        inputAttributes,
                        "type"
                    ) || "text"
                ).toLowerCase();

            const value =
                getAttribute(
                    inputAttributes,
                    "value"
                );

            inputs.push({
                name,
                type,
                value
            });
        }


        // -------------------------------------------------
        // TEXTAREA ELEMENTS
        // -------------------------------------------------

        const textareaRegex =
            /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;

        let textareaMatch;

        while (
            (textareaMatch =
                textareaRegex.exec(
                    formBody
                )) !== null
        ) {
            const attributesText =
                textareaMatch[1] || "";

            const name =
                getAttribute(
                    attributesText,
                    "name"
                );

            if (!name) {
                continue;
            }

            const value =
                textareaMatch[2] || "";

            inputs.push({
                name,
                type:
                    "textarea",
                value:
                    value.trim()
            });
        }


        // -------------------------------------------------
        // SELECT ELEMENTS
        // -------------------------------------------------

        const selectRegex =
            /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;

        let selectMatch;

        while (
            (selectMatch =
                selectRegex.exec(
                    formBody
                )) !== null
        ) {
            const attributesText =
                selectMatch[1] || "";

            const selectBody =
                selectMatch[2] || "";

            const name =
                getAttribute(
                    attributesText,
                    "name"
                );

            if (!name) {
                continue;
            }

            const optionMatch =
                selectBody.match(
                    /<option\b([^>]*)>([\s\S]*?)<\/option>/i
                );

            let value = "1";

            if (optionMatch) {
                value =
                    getAttribute(
                        optionMatch[1] || "",
                        "value"
                    );

                if (!value) {
                    value =
                        (
                            optionMatch[2] || ""
                        ).trim();
                }
            }

            inputs.push({
                name,
                type:
                    "select",
                value
            });
        }


        if (
            inputs.length === 0
        ) {
            continue;
        }


        forms.push({
            action,

            method:
                (
                    methodValue || "GET"
                ).toUpperCase(),

            source:
                baseUrl,

            inputs
        });


        if (
            forms.length >=
            MAX_FORMS
        ) {
            break;
        }
    }

    return forms;
}


// =========================================================
// SQL ERROR DETECTION
// =========================================================

function looksLikeSqlError(
    body
) {
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
        (pattern) =>
            pattern.test(body)
    );
}


// =========================================================
// NORMALIZE RESPONSE
// Used to compare responses while ignoring
// the random scanner marker.
// =========================================================

function normalizeBody(
    body
) {
    return body
        .replace(
            /\s+/g,
            " "
        )
        .trim();
}


// =========================================================
// BUILD QUERY
// =========================================================

function buildQuery(
    url,
    parameter,
    value
) {
    const target =
        new URL(url);

    target.searchParams.set(
        parameter,
        value
    );

    return target.toString();
}


// =========================================================
// BUILD FORM DATA
// =========================================================

function buildFormData(
    form,
    testedParameter,
    testedValue
) {
    const data = {};

    for (
        const input
        of form.inputs
    ) {
        const type =
            input.type.toLowerCase();

        // Do not submit file/password controls.
        if (
            [
                "file",
                "password",
                "button",
                "reset"
            ].includes(type)
        ) {
            continue;
        }

        if (
            type === "submit"
        ) {
            if (input.name) {
                data[input.name] =
                    input.value ||
                    "Submit";
            }

            continue;
        }

        if (
            type === "checkbox" ||
            type === "radio"
        ) {
            continue;
        }

        if (
            input.name ===
            testedParameter
        ) {
            data[input.name] =
                testedValue;
        } else {
            data[input.name] =
                input.value ||
                "1";
        }
    }

    return data;
}


// =========================================================
// ADD FINDING
// =========================================================

function addFinding(
    findings,
    seen,
    finding
) {
    const key =
        [
            finding.vulnerability,
            finding.affected_module
        ].join("|");

    if (
        seen.has(key)
    ) {
        return;
    }

    seen.add(key);

    findings.push(
        finding
    );
}


// =========================================================
// TEST XSS
// =========================================================

async function testXss(
    client,
    requestInfo,
    parameter,
    baselineBody,
    findings,
    seen
) {
    const marker =
        "VAPT_REFLECT_" +
        Math.random()
            .toString(36)
            .slice(2, 10);

    const payload =
        "\"><vapt-" +
        marker +
        ">";


    try {
        let response;

        if (
            requestInfo.method ===
            "GET"
        ) {
            response =
                await fetchPage(
                    client,
                    buildQuery(
                        requestInfo.url,
                        parameter,
                        payload
                    )
                );

        } else {
            const formData =
                buildFormData(
                    requestInfo.form,
                    parameter,
                    payload
                );

            response =
                await postForm(
                    client,
                    requestInfo.url,
                    formData
                );
        }


        if (
            response.body.includes(
                marker
            )
        ) {
            addFinding(
                findings,
                seen,
                {
                    vulnerability:
                        "Reflected XSS",

                    affected_module:
                        new URL(
                            requestInfo.url
                        ).pathname +
                        " [" +
                        parameter +
                        "]",

                    description:
                        "A unique scanner marker supplied through an application input was reflected in the HTTP response without being removed.",

                    observed_result:
                        "The marker " +
                        marker +
                        " was returned by parameter " +
                        parameter +
                        ".",

                    impact:
                        "Reflected user input may become executable client-side content when the application places the value into an unsafe HTML or script context.",

                    severity:
                        "High",

                    status:
                        "Open"
                }
            );
        }

    } catch {
        // Ignore individual test failures.
    }
}


// =========================================================
// TEST SQL INJECTION
// =========================================================

async function testSqlInjection(
    client,
    requestInfo,
    parameter,
    baselineBody,
    findings,
    seen
) {
    const sqlTests = [
        "'",
        "\"",
        "1' OR '1'='1",
        "1' OR '1'='2"
    ];


    for (
        const payload
        of sqlTests
    ) {
        try {
            let response;

            if (
                requestInfo.method ===
                "GET"
            ) {
                response =
                    await fetchPage(
                        client,
                        buildQuery(
                            requestInfo.url,
                            parameter,
                            payload
                        )
                    );

            } else {
                const formData =
                    buildFormData(
                        requestInfo.form,
                        parameter,
                        payload
                    );

                response =
                    await postForm(
                        client,
                        requestInfo.url,
                        formData
                    );
            }


            const sqlError =
                looksLikeSqlError(
                    response.body
                );


            const bodyDifference =
                Math.abs(
                    normalizeBody(
                        response.body
                    ).length -
                    normalizeBody(
                        baselineBody
                    ).length
                );


            if (
                sqlError &&
                (
                    bodyDifference > 10 ||
                    payload === "'"
                )
            ) {
                addFinding(
                    findings,
                    seen,
                    {
                        vulnerability:
                            "SQL Injection",

                        affected_module:
                            new URL(
                                requestInfo.url
                            ).pathname +
                            " [" +
                            parameter +
                            "]",

                        description:
                            "A controlled SQL metacharacter/payload produced SQL-related error behavior in the application response.",

                        observed_result:
                            "SQL error indicators were detected after testing parameter " +
                            parameter +
                            " with a controlled SQL payload.",

                        impact:
                            "An attacker may be able to alter database queries, retrieve unauthorized records, or otherwise manipulate database operations.",

                        severity:
                            "High",

                        status:
                            "Open"
                    }
                );

                return;
            }

        } catch {
            // Ignore individual test failures.
        }
    }
}


// =========================================================
// TEST A FORM
// =========================================================

async function testForm(
    client,
    form,
    findings,
    seen
) {
    const testableInputs =
        form.inputs.filter(
            (input) => {
                const type =
                    input.type.toLowerCase();

                return ![
                    "hidden",
                    "submit",
                    "button",
                    "reset",
                    "file",
                    "password",
                    "checkbox",
                    "radio"
                ].includes(type);
            }
        );


    for (
        const input
        of testableInputs
    ) {
        const baselineData =
            buildFormData(
                form,
                input.name,
                input.value ||
                    "1"
            );


        try {
            const baseline =
                form.method ===
                "POST"
                    ? await postForm(
                        client,
                        form.action,
                        baselineData
                    )
                    : await fetchPage(
                        client,
                        buildQuery(
                            form.action,
                            input.name,
                            input.value ||
                                "1"
                        )
                    );


            await testXss(
                client,
                {
                    method:
                        form.method,

                    url:
                        form.action,

                    form
                },

                input.name,

                baseline.body,

                findings,

                seen
            );


            await testSqlInjection(
                client,
                {
                    method:
                        form.method,

                    url:
                        form.action,

                    form
                },

                input.name,

                baseline.body,

                findings,

                seen
            );

        } catch {
            // Ignore individual form failures.
        }
    }
}


// =========================================================
// TEST URL PARAMETERS
// =========================================================

async function testUrlParameters(
    client,
    pageUrl,
    baselineBody,
    findings,
    seen
) {
    const url =
        new URL(pageUrl);

    const parameters =
        Array.from(
            url.searchParams.keys()
        );

    for (
        const parameter
        of parameters
    ) {
        const requestInfo = {
            method:
                "GET",

            url:
                pageUrl
        };


        await testXss(
            client,
            requestInfo,
            parameter,
            baselineBody,
            findings,
            seen
        );


        await testSqlInjection(
            client,
            requestInfo,
            parameter,
            baselineBody,
            findings,
            seen
        );
    }
}


// =========================================================
// DVWA LOGIN
// =========================================================

function getDvwaBaseUrl(
    targetUrl
) {
    const target =
        new URL(targetUrl);

    let path =
        target.pathname;

    if (
        !path.endsWith("/")
    ) {
        path += "/";
    }

    return (
        target.origin +
        path
    );
}


function extractUserToken(
    html
) {
    const patterns = [
        /name\s*=\s*["']user_token["'][^>]*value\s*=\s*["']([^"']+)["']/i,

        /value\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']user_token["']/i
    ];

    for (
        const pattern
        of patterns
    ) {
        const match =
            html.match(
                pattern
            );

        if (match) {
            return match[1];
        }
    }

    return null;
}


async function loginToDvwa(
    client,
    targetUrl
) {
    const baseUrl =
        getDvwaBaseUrl(
            targetUrl
        );

    const loginUrl =
        new URL(
            "login.php",
            baseUrl
        ).toString();


    // -------------------------------------------------
    // GET LOGIN PAGE
    // -------------------------------------------------

    const loginPage =
        await fetchPage(
            client,
            loginUrl
        );


    const token =
        extractUserToken(
            loginPage.body
        );


    if (!token) {
        throw new Error(
            "DVWA login token was not found on login.php."
        );
    }


    // -------------------------------------------------
    // CREDENTIALS
    // -------------------------------------------------

    const username =
        process.env.DVWA_USERNAME ||
        "admin";

    const password =
        process.env.DVWA_PASSWORD ||
        "password";


    // -------------------------------------------------
    // LOGIN
    // -------------------------------------------------

    const loginResponse =
        await postForm(
            client,
            loginUrl,
            {
                username,
                password,
                Login:
                    "Login",
                user_token:
                    token
            }
        );


    // -------------------------------------------------
    // VERIFY LOGIN
    // -------------------------------------------------

    if (
        /name\s*=\s*["']username["']/i.test(
            loginResponse.body
        ) &&
        /login/i.test(
            loginResponse.body
        )
    ) {
        throw new Error(
            "DVWA login failed. Check DVWA_USERNAME and DVWA_PASSWORD."
        );
    }


    // -------------------------------------------------
    // SET SECURITY LEVEL
    // -------------------------------------------------

    const securityLevel =
        process.env.DVWA_SECURITY_LEVEL ||
        "low";


    if (
        [
            "low",
            "medium",
            "high",
            "impossible"
        ].includes(
            securityLevel
        )
    ) {
        client.setCookie(
            "security",
            securityLevel
        );
    }


    // -------------------------------------------------
    // VERIFY AUTHENTICATED PAGE
    // -------------------------------------------------

    const authenticatedPage =
        await fetchPage(
            client,
            new URL(
                "index.php",
                baseUrl
            ).toString()
        );


    const looksAuthenticated =
        /Logout/i.test(
            authenticatedPage.body
        ) ||
        /Security Level:/i.test(
            authenticatedPage.body
        );


    if (
        !looksAuthenticated
    ) {
        throw new Error(
            "DVWA authentication could not be verified."
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
    const headerTests = [
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


    for (
        const [
            headerName,
            title
        ]
        of headerTests
    ) {
        if (
            !response.headers[
                headerName
            ]
        ) {
            addFinding(
                findings,
                seen,
                {
                    vulnerability:
                        title,

                    affected_module:
                        new URL(
                            response.url
                        ).pathname,

                    description:
                        "The HTTP response does not include the recommended security header.",

                    observed_result:
                        headerName +
                        " was absent from the response.",

                    impact:
                        "Missing browser security controls can increase exposure to common web attacks.",

                    severity:
                        "Low",

                    status:
                        "Open"
                }
            );
        }
    }
}


// =========================================================
// MAIN SCANNER
// =========================================================

async function scanTarget(
    targetUrl
) {
    const startedAt =
        Date.now();


    const target =
        new URL(
            targetUrl
        );


    if (
        ![
            "http:",
            "https:"
        ].includes(
            target.protocol
        )
    ) {
        throw new Error(
            "Target URL must use HTTP or HTTPS."
        );
    }


    // -------------------------------------------------
    // LAB TARGET RESTRICTION
    // -------------------------------------------------

    if (
        ![
            "localhost",
            "127.0.0.1"
        ].includes(
            target.hostname
        )
    ) {
        throw new Error(
            "This scanner is restricted to localhost/127.0.0.1 targets."
        );
    }


    const client =
        new SessionClient();


    const discovered =
        new Set([
            target.toString()
        ]);


    const queue = [
        target.toString()
    ];


    const pages = [];

    const findings = [];

    const seen =
        new Set();


    // -------------------------------------------------
    // AUTHENTICATE TO DVWA
    // -------------------------------------------------

    const authentication =
        await loginToDvwa(
            client,
            targetUrl
        );


    // -------------------------------------------------
    // CRAWL
    // -------------------------------------------------

    while (
        queue.length &&
        pages.length < MAX_PAGES
    ) {
        const current =
            queue.shift();


        if (
            !shouldCrawl(
                current
            )
        ) {
            continue;
        }


        try {
            const response =
                await fetchPage(
                    client,
                    current
                );


            pages.push({
                url:
                    response.url,

                status:
                    response.status
            });


            // -------------------------------------------------
            // SECURITY HEADERS
            // -------------------------------------------------

            checkSecurityHeaders(
                response,
                findings,
                seen
            );


            const contentType =
                response.headers[
                    "content-type"
                ] || "";


            if (
                !contentType.includes(
                    "text/html"
                )
            ) {
                continue;
            }


            // -------------------------------------------------
            // DISCOVER LINKS
            // -------------------------------------------------

            const links =
                discoverLinks(
                    response.body,
                    response.url
                );


            for (
                const link
                of links
            ) {
                if (
                    !sameHost(
                        link,
                        targetUrl
                    )
                ) {
                    continue;
                }


                if (
                    !shouldCrawl(
                        link
                    )
                ) {
                    continue;
                }


                if (
                    !discovered.has(
                        link
                    ) &&
                    discovered.size <
                        MAX_PAGES
                ) {
                    discovered.add(
                        link
                    );

                    queue.push(
                        link
                    );
                }
            }


            // -------------------------------------------------
            // DISCOVER FORMS
            // -------------------------------------------------

            const forms =
                discoverForms(
                    response.body,
                    response.url
                );


            for (
                const form
                of forms
            ) {
                await testForm(
                    client,
                    form,
                    findings,
                    seen
                );
            }


            // -------------------------------------------------
            // URL PARAMETERS
            // -------------------------------------------------

            await testUrlParameters(
                client,
                response.url,
                response.body,
                findings,
                seen
            );


        } catch (error) {
            pages.push({
                url:
                    current,

                status:
                    "error",

                error:
                    error.name ===
                    "AbortError"
                        ? "timeout"
                        : error.message
            });
        }
    }


    const durationMs =
        Date.now() -
        startedAt;


    return {
        target_url:
            target.toString(),

        authenticated:
            true,

        authentication,

        security_level:
            authentication.securityLevel,

        pages_scanned:
            pages.length,

        duration_ms:
            durationMs,

        findings,

        pages
    };
}


module.exports = {
    scanTarget
};