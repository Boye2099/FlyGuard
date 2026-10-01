const securityHeaders =
    document.getElementById("securityHeaders");

const cookieStatus =
    document.getElementById("cookieStatus");

const domain =
    document.getElementById("domain");

const url =
    document.getElementById("url");

const protocol =
    document.getElementById("protocol");

const httpsStatus =
    document.getElementById("httpsStatus");

const pageTitle =
    document.getElementById("pageTitle");

const pageSize =
    document.getElementById("pageSize");

const linkCount =
    document.getElementById("linkCount");

const scriptCount =
    document.getElementById("scriptCount");

const imageCount =
    document.getElementById("imageCount");

const formCount =
    document.getElementById("formCount");

const iframeCount =
    document.getElementById("iframeCount");

const externalCount =
    document.getElementById("externalCount");

const thirdPartyDomains =
    document.getElementById("thirdPartyDomains");

const securityFindings =
    document.getElementById("securityFindings");

const scanButton =
    document.getElementById("scanButton");

const buttonText =
    document.getElementById("buttonText");

const message =
    document.getElementById("message");

const scanHistory =
    document.getElementById("scanHistory");


/*
 * Analyze the current webpage.
 */
async function analyzePage() {

    const currentUrl =
        window.location.href;

    const currentOrigin =
        window.location.origin;

    const currentProtocol =
        window.location.protocol;


    const links =
        document.querySelectorAll("a[href]");

    const scripts =
        document.querySelectorAll("script");

    const images =
        document.querySelectorAll("img[src]");

    const forms =
        document.querySelectorAll("form");

    const iframes =
        document.querySelectorAll("iframe[src]");


    const resources =
        document.querySelectorAll(
            "script[src], img[src], iframe[src], link[href]"
        );


    /*
     * Find third-party domains.
     */
    const thirdParty =
        new Set();


    resources.forEach((resource) => {

        const source =
            resource.src ||
            resource.href;


        if (!source) {
            return;
        }


        try {

            const resourceUrl =
                new URL(source);


            if (
                resourceUrl.origin !==
                currentOrigin
            ) {

                thirdParty.add(
                    resourceUrl.hostname
                );

            }

        } catch {

            // Ignore invalid resource URLs.

        }

    });


    /*
     * Calculate page HTML size.
     */
    const pageSizeBytes =
        new Blob([
            document.documentElement.outerHTML
        ]).size;


    /*
     * Check HTTPS.
     */
    const isHttps =
        currentProtocol === "https:";


    /*
     * Find password fields.
     */
    const passwordFields =
        document.querySelectorAll(
            'input[type="password"]'
        );


    /*
     * Find insecure forms.
     */
    const insecureForms =
        Array.from(forms).filter((form) => {

            const action =
                form.getAttribute("action");


            if (!action) {
                return false;
            }


            try {

                const formUrl =
                    new URL(
                        action,
                        currentUrl
                    );


                return (
                    isHttps &&
                    formUrl.protocol === "http:"
                );

            } catch {

                return false;

            }

        });


    /*
     * Check for mixed content.
     */
    const mixedContent =
        isHttps &&
        Array.from(resources).some(
            (resource) => {

                const source =
                    resource.src ||
                    resource.href;


                if (!source) {
                    return false;
                }


                try {

                    return (
                        new URL(source)
                            .protocol === "http:"
                    );

                } catch {

                    return false;

                }

            }
        );


    /*
     * Find inline scripts.
     */
    const inlineScripts =
        Array.from(scripts).filter(
            (script) =>
                !script.src &&
                script.textContent.trim()
        );


    /*
     * Find external scripts.
     */
    const externalScripts =
        Array.from(scripts).filter(
            (script) =>
                script.src
        );


    /*
     * Check for CSP.
     */
    const csp =
        document.querySelector(
            'meta[http-equiv="Content-Security-Policy"]'
        );


    /*
     * Count accessible cookies.
     */
    const cookieCount =
        document.cookie
            ? document.cookie
                .split(";")
                .filter(Boolean)
                .length
            : 0;


    /*
     * Security headers.
     */
    const headers = {

        "X-Frame-Options":
            "Not detected",

        "X-Content-Type-Options":
            "Not detected",

        "Referrer-Policy":
            "Not detected",

        "Permissions-Policy":
            "Not detected"

    };


    /*
     * Attempt to inspect response headers.
     */
    try {

        const response =
            await fetch(
                window.location.href,
                {
                    method: "GET",
                    credentials: "same-origin"
                }
            );


        headers["X-Frame-Options"] =
            response.headers.get(
                "X-Frame-Options"
            ) ||
            "Not detected";


        headers["X-Content-Type-Options"] =
            response.headers.get(
                "X-Content-Type-Options"
            ) ||
            "Not detected";


        headers["Referrer-Policy"] =
            response.headers.get(
                "Referrer-Policy"
            ) ||
            "Not detected";


        headers["Permissions-Policy"] =
            response.headers.get(
                "Permissions-Policy"
            ) ||
            "Not detected";


    } catch {

        /*
         * Header inspection can fail because
         * of browser restrictions.
         */

    }


    return {

        domain:
            window.location.hostname,

        url:
            currentUrl,

        protocol:
            currentProtocol,

        isHttps,

        title:
            document.title ||
            "Untitled",

        pageSize:
            pageSizeBytes,

        links:
            links.length,

        scripts:
            scripts.length,

        images:
            images.length,

        forms:
            forms.length,

        iframes:
            iframes.length,

        resources:
            resources.length,

        thirdPartyDomains:
            Array.from(thirdParty),

        passwordFields:
            passwordFields.length,

        insecureForms:
            insecureForms.length,

        mixedContent,

        inlineScripts:
            inlineScripts.length,

        externalScripts:
            externalScripts.length,

        hasCsp:
            Boolean(csp),

        cookieCount,

        headers

    };

}


/*
 * Calculate security score.
 */
function calculateSecurityScore(data) {

    let score = 100;

    const deductions = [];


    if (!data.isHttps) {

        score -= 30;

        deductions.push({

            points: 30,

            reason:
                "The page is not using HTTPS."

        });

    }


    if (data.insecureForms > 0) {

        score -= 20;

        deductions.push({

            points: 20,

            reason:
                "A form submits data over HTTP."

        });

    }


    if (data.mixedContent) {

        score -= 15;

        deductions.push({

            points: 15,

            reason:
                "The HTTPS page loads insecure HTTP resources."

        });

    }


    if (
        data.passwordFields > 0 &&
        !data.isHttps
    ) {

        score -= 20;

        deductions.push({

            points: 20,

            reason:
                "A password field exists on a non-HTTPS page."

        });

    }


    if (!data.hasCsp) {

        score -= 5;

        deductions.push({

            points: 5,

            reason:
                "No Content Security Policy was detected."

        });

    }


    if (
        data.headers[
            "X-Content-Type-Options"
        ] === "Not detected"
    ) {

        score -= 3;

        deductions.push({

            points: 3,

            reason:
                "X-Content-Type-Options was not detected."

        });

    }


    if (
        data.headers[
            "X-Frame-Options"
        ] === "Not detected"
    ) {

        score -= 3;

        deductions.push({

            points: 3,

            reason:
                "X-Frame-Options was not detected."

        });

    }


    if (
        data.headers[
            "Referrer-Policy"
        ] === "Not detected"
    ) {

        score -= 2;

        deductions.push({

            points: 2,

            reason:
                "Referrer-Policy was not detected."

        });

    }


    score =
        Math.max(0, score);


    return {

        score,

        deductions

    };

}


/*
 * Display security score.
 */
function displaySecurityScore(data) {

    const existingScore =
        document.getElementById(
            "securityScore"
        );


    if (!existingScore) {
        return;
    }


    const result =
        calculateSecurityScore(data);


    existingScore.textContent =
        `${result.score}/100`;


    existingScore.className =
        "score-value";


    if (result.score >= 80) {

        existingScore.classList.add(
            "good"
        );

    } else if (result.score >= 60) {

        existingScore.classList.add(
            "moderate"
        );

    } else {

        existingScore.classList.add(
            "low"
        );

    }

}


/*
 * Save scan to Chrome local storage.
 */
async function saveScan(data) {

    const score =
        calculateSecurityScore(data).score;


    const stored =
        await chrome.storage.local.get(
            "scanHistory"
        );


    const history =
        stored.scanHistory || [];


    const scan = {

        domain:
            data.domain,

        score:
            score,

        timestamp:
            Date.now()

    };


    /*
     * Put newest scan first.
     */
    history.unshift(scan);


    /*
     * Keep the five most recent scans.
     */
    const recentScans =
        history.slice(0, 5);


    await chrome.storage.local.set({

        scanHistory:
            recentScans

    });


    displayScanHistory(
        recentScans
    );

}


/*
 * Load scan history.
 */
async function loadScanHistory() {

    const stored =
        await chrome.storage.local.get(
            "scanHistory"
        );


    displayScanHistory(
        stored.scanHistory || []
    );

}


/*
 * Display scan history.
 */
function displayScanHistory(history) {

    if (!scanHistory) {
        return;
    }


    scanHistory.innerHTML = "";


    if (history.length === 0) {

        scanHistory.innerHTML =
            '<span class="empty">No previous scans</span>';

        return;

    }


    history.forEach((scan) => {

        const item =
            document.createElement("div");


        item.className =
            "history-item";


        const date =
            new Date(
                scan.timestamp
            );


        item.innerHTML = `

            <div>

                <strong>
                    ${escapeHtml(scan.domain)}
                </strong>

                <span>
                    ${formatScanDate(date)}
                </span>

            </div>

            <strong class="history-score">
                ${scan.score}/100
            </strong>

        `;


        scanHistory.appendChild(
            item
        );

    });

}


/*
 * Format scan date.
 */
function formatScanDate(date) {

    return date.toLocaleString(
        [],
        {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );

}


/*
 * Escape text before inserting
 * stored domain names into HTML.
 */
function escapeHtml(value) {

    const element =
        document.createElement("div");

    element.textContent =
        value;

    return element.innerHTML;

}


/*
 * Display third-party domains.
 */
function displayThirdPartyDomains(domains) {

    thirdPartyDomains.innerHTML = "";


    if (domains.length === 0) {

        thirdPartyDomains.innerHTML =
            '<span class="empty">None detected</span>';

        return;

    }


    domains.forEach((hostname) => {

        const item =
            document.createElement("span");


        item.className =
            "domain-item";


        item.textContent =
            hostname;


        thirdPartyDomains.appendChild(
            item
        );

    });

}


/*
 * Display security findings.
 */
function displaySecurityFindings(data) {

    securityFindings.innerHTML = "";


    const findings = [];


    if (data.isHttps) {

        findings.push({

            type:
                "safe",

            mark:
                "✓",

            title:
                "HTTPS enabled",

            description:
                "The page is using an encrypted connection."

        });

    } else {

        findings.push({

            type:
                "warning",

            mark:
                "!",

            title:
                "HTTPS not detected",

            description:
                "The page is not using an encrypted connection."

        });

    }


    if (data.passwordFields > 0) {

        findings.push({

            type:
                data.isHttps
                    ? "info"
                    : "warning",

            mark:
                data.isHttps
                    ? "i"
                    : "!",

            title:
                `${data.passwordFields} password field detected`,

            description:
                data.isHttps
                    ? "Password input exists on this page."
                    : "A password field exists on a non-HTTPS page."

        });

    }


    if (data.insecureForms > 0) {

        findings.push({

            type:
                "warning",

            mark:
                "!",

            title:
                "Insecure form submission",

            description:
                "A form submits data over HTTP."

        });

    }


    if (data.mixedContent) {

        findings.push({

            type:
                "warning",

            mark:
                "!",

            title:
                "Mixed content detected",

            description:
                "The page loads resources over HTTP."

        });

    }


    if (data.inlineScripts > 0) {

        findings.push({

            type:
                "info",

            mark:
                "i",

            title:
                "Inline scripts detected",

            description:
                `${data.inlineScripts} inline script element(s) found.`

        });

    }


    if (data.externalScripts > 0) {

        findings.push({

            type:
                "info",

            mark:
                "i",

            title:
                "External JavaScript detected",

            description:
                `${data.externalScripts} external script(s) found.`

        });

    }


    if (data.hasCsp) {

        findings.push({

            type:
                "safe",

            mark:
                "✓",

            title:
                "Content Security Policy detected",

            description:
                "A CSP meta policy was found on the page."

        });

    } else {

        findings.push({

            type:
                "info",

            mark:
                "i",

            title:
                "No CSP meta policy detected",

            description:
                "A Content Security Policy meta tag was not found."

        });

    }


    if (
        data.thirdPartyDomains.length > 0
    ) {

        findings.push({

            type:
                "info",

            mark:
                "i",

            title:
                "Third-party resources detected",

            description:
                `${data.thirdPartyDomains.length} third-party domain(s) found.`

        });

    }


    findings.forEach((finding) => {

        const element =
            document.createElement("div");


        element.className =
            `finding ${finding.type}`;


        element.innerHTML = `

            <span class="finding-mark">
                ${finding.mark}
            </span>

            <div>

                <strong>
                    ${finding.title}
                </strong>

                <p>
                    ${finding.description}
                </p>

            </div>

        `;


        securityFindings.appendChild(
            element
        );

    });

}


/*
 * Display security headers.
 */
function displaySecurityHeaders(headers) {

    securityHeaders.innerHTML = "";


    Object.entries(headers).forEach(
        ([name, value]) => {

            const item =
                document.createElement("div");


            item.className =
                "header-item";


            item.innerHTML = `

                <span>
                    ${name}
                </span>

                <strong>
                    ${value}
                </strong>

            `;


            securityHeaders.appendChild(
                item
            );

        }
    );

}


/*
 * Display cookie information.
 */
function displayCookieStatus(count) {

    if (count === 0) {

        cookieStatus.textContent =
            "No accessible cookies detected";

    } else {

        cookieStatus.textContent =
            `${count} accessible cookie(s) detected`;

    }

}


/*
 * Display all analysis results.
 */
function displayResults(data) {

    domain.textContent =
        data.domain;


    url.textContent =
        data.url;


    protocol.textContent =
        data.protocol
            .replace(":", "")
            .toUpperCase();


    httpsStatus.textContent =
        data.isHttps
            ? "HTTPS"
            : "HTTP";


    pageTitle.textContent =
        data.title;


    pageSize.textContent =
        formatBytes(
            data.pageSize
        );


    linkCount.textContent =
        data.links;


    scriptCount.textContent =
        data.scripts;


    imageCount.textContent =
        data.images;


    formCount.textContent =
        data.forms;


    iframeCount.textContent =
        data.iframes;


    externalCount.textContent =
        data.resources;


    displayThirdPartyDomains(
        data.thirdPartyDomains
    );


    displaySecurityFindings(
        data
    );


    displaySecurityHeaders(
        data.headers
    );


    displayCookieStatus(
        data.cookieCount
    );


    displaySecurityScore(
        data
    );


    message.textContent =
        "Analysis completed";

}


/*
 * Convert bytes to a readable size.
 */
function formatBytes(bytes) {

    if (bytes === 0) {
        return "0 Bytes";
    }


    const units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];


    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );


    return `${(
        bytes /
        Math.pow(1024, index)
    ).toFixed(1)} ${units[index]}`;

}


/*
 * Analyze the active browser tab.
 */
async function analyzeCurrentPage() {

    buttonText.textContent =
        "Analyzing...";


    scanButton.disabled =
        true;


    message.textContent =
        "Inspecting page security signals...";


    try {

        const tabs =
            await chrome.tabs.query({

                active:
                    true,

                currentWindow:
                    true

            });


        const activeTab =
            tabs[0];


        if (
            !activeTab ||
            !activeTab.id
        ) {

            throw new Error(
                "No active tab found."
            );

        }


        if (
            activeTab.url.startsWith(
                "chrome://"
            ) ||
            activeTab.url.startsWith(
                "chrome-extension://"
            )
        ) {

            throw new Error(
                "This page cannot be analyzed."
            );

        }


        const results =
            await chrome.scripting.executeScript({

                target: {

                    tabId:
                        activeTab.id

                },

                func:
                    analyzePage

            });


        const data =
            results[0].result;


        displayResults(
            data
        );


        /*
         * Save only after a successful analysis.
         */
        await saveScan(
            data
        );


    } catch (error) {

        console.error(
            error
        );


        message.textContent =
            error.message ||
            "Analysis failed.";


    } finally {

        buttonText.textContent =
            "Analyze page";


        scanButton.disabled =
            false;

    }

}


/*
 * Analyze button.
 */
scanButton.addEventListener(
    "click",
    analyzeCurrentPage
);


/*
 * Load history when popup opens.
 */
loadScanHistory();


/*
 * Analyze current page when popup opens.
 */
analyzeCurrentPage();