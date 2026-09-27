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
    document.getElementById(
        "thirdPartyDomains"
    );

const securityFindings =
    document.getElementById(
        "securityFindings"
    );

const scanButton =
    document.getElementById("scanButton");

const buttonText =
    document.getElementById("buttonText");

const message =
    document.getElementById("message");


function formatBytes(bytes) {

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {

        return `${(
            bytes / 1024
        ).toFixed(1)} KB`;

    }

    return `${(
        bytes / (1024 * 1024)
    ).toFixed(2)} MB`;
}


function showMessage(text) {

    message.textContent = text;

}


/*
 * Inspect the active webpage and collect
 * information that can be used for
 * basic security checks.
 */

async function analyzePage() {

    const hostname =
        window.location.hostname;


    const resources = [

        ...document.querySelectorAll(
            "script[src]"
        ),

        ...document.querySelectorAll(
            "img[src]"
        ),

        ...document.querySelectorAll(
            "iframe[src]"
        ),

        ...document.querySelectorAll(
            "link[href]"
        )

    ];


    const thirdPartyDomains =
        new Set();


    resources.forEach(resource => {

        const source =
            resource.src ||
            resource.href;


        if (!source) {
            return;
        }


        try {

            const resourceURL =
                new URL(
                    source,
                    window.location.href
                );


            if (
                resourceURL.hostname &&
                resourceURL.hostname !== hostname
            ) {

                thirdPartyDomains.add(
                    resourceURL.hostname
                );

            }

        } catch {

            // Ignore invalid resource URLs

        }

    });


    const pageSize =
        new Blob([
            document.documentElement
                .outerHTML
        ]).size;


    /*
     * Find forms that contain password
     * fields.
     */

    const passwordForms = [];


    document
        .querySelectorAll("form")
        .forEach(form => {

            const passwordField =
                form.querySelector(
                    'input[type="password"]'
                );


            if (passwordField) {

                passwordForms.push(
                    form
                );

            }

        });


    /*
     * Find forms that submit their
     * data over HTTP.
     */

    const insecureForms = [];


    document
        .querySelectorAll("form")
        .forEach(form => {

            const action =
                form.getAttribute("action");


            if (!action) {
                return;
            }


            try {

                const formURL =
                    new URL(
                        action,
                        window.location.href
                    );


                if (
                    window.location.protocol ===
                        "https:" &&
                    formURL.protocol ===
                        "http:"
                ) {

                    insecureForms.push(
                        formURL.href
                    );

                }

            } catch {

                // Ignore invalid form URLs

            }

        });


    /*
     * Look for HTTP resources loaded
     * by an HTTPS page.
     */

    const mixedContent = [];


    if (
        window.location.protocol ===
        "https:"
    ) {

        resources.forEach(resource => {

            const source =
                resource.src ||
                resource.href;


            if (!source) {
                return;
            }


            try {

                const resourceURL =
                    new URL(
                        source,
                        window.location.href
                    );


                if (
                    resourceURL.protocol ===
                    "http:"
                ) {

                    mixedContent.push(
                        resourceURL.href
                    );

                }

            } catch {

                // Ignore invalid URLs

            }

        });

    }


    /*
     * Count inline JavaScript.
     */

    const inlineScripts =
        document.querySelectorAll(
            "script:not([src])"
        ).length;


    /*
     * Count external JavaScript.
     */

    const externalScripts =
        document.querySelectorAll(
            "script[src]"
        ).length;


    /*
     * Check for a Content Security
     * Policy declared through a
     * meta tag.
     */

    const cspMeta =
        document.querySelector(
            'meta[http-equiv="Content-Security-Policy"]'
        );


    /*
     * Count cookies accessible to
     * JavaScript.
     */

    const cookies =
        document.cookie;


    const cookieCount =
        cookies
            ? cookies.split(";").length
            : 0;


    /*
     * Check selected security headers.
     */

    let headerResults = {

        xFrameOptions:
            "Not checked",

        contentTypeOptions:
            "Not checked",

        referrerPolicy:
            "Not checked",

        permissionsPolicy:
            "Not checked"

    };


    try {

        const response =
            await fetch(
                window.location.href,
                {
                    method: "GET",
                    credentials: "same-origin"
                }
            );


        headerResults = {

            xFrameOptions:
                response.headers.get(
                    "X-Frame-Options"
                ) || "Not detected",


            contentTypeOptions:
                response.headers.get(
                    "X-Content-Type-Options"
                ) || "Not detected",


            referrerPolicy:
                response.headers.get(
                    "Referrer-Policy"
                ) || "Not detected",


            permissionsPolicy:
                response.headers.get(
                    "Permissions-Policy"
                ) || "Not detected"

        };


    } catch (error) {

        console.log(
            "Could not inspect response headers:",
            error
        );

    }


    return {

        headers:
            headerResults,

        cookieCount:
            cookieCount,

        hostname,

        origin:
            window.location.origin,

        protocol:
            window.location.protocol
                .replace(":", ""),

        isHttps:
            window.location.protocol ===
            "https:",

        title:
            document.title ||
            "Untitled",

        pageSize,

        links:
            document.querySelectorAll(
                "a"
            ).length,

        scripts:
            document.querySelectorAll(
                "script"
            ).length,

        images:
            document.querySelectorAll(
                "img"
            ).length,

        forms:
            document.querySelectorAll(
                "form"
            ).length,

        iframes:
            document.querySelectorAll(
                "iframe"
            ).length,

        externalResources:
            resources.length,

        thirdPartyDomains:
            Array.from(
                thirdPartyDomains
            ).sort(),

        passwordForms:
            passwordForms.length,

        insecureForms:
            insecureForms,

        mixedContent:
            mixedContent,

        inlineScripts,

        externalScripts,

        hasCsp:
            Boolean(cspMeta)

    };

}


/*
 * Display the reconnaissance results.
 */

function displayResults(data) {

    domain.textContent =
        data.hostname;


    url.textContent =
        data.origin;


    protocol.textContent =
        data.protocol.toUpperCase();


    httpsStatus.textContent =
        data.isHttps
            ? "Enabled"
            : "Not enabled";


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
        data.externalResources;


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

}


/*
 * Display third-party domains.
 */

function displayThirdPartyDomains(domains) {

    thirdPartyDomains.innerHTML = "";


    if (domains.length === 0) {

        const empty =
            document.createElement(
                "span"
            );


        empty.className =
            "empty";


        empty.textContent =
            "No third-party domains detected";


        thirdPartyDomains.appendChild(
            empty
        );


        return;

    }


    domains.forEach(domainName => {

        const item =
            document.createElement(
                "div"
            );


        item.className =
            "domain-item";


        item.textContent =
            domainName;


        thirdPartyDomains.appendChild(
            item
        );

    });

}


/*
 * Create a security finding element.
 */

function createFinding(
    status,
    title,
    description,
    type
) {

    const finding =
        document.createElement(
            "div"
        );


    finding.className =
        `finding ${type}`;


    const statusElement =
        document.createElement(
            "span"
        );


    statusElement.className =
        "finding-status";


    statusElement.textContent =
        status;


    const content =
        document.createElement(
            "div"
        );


    const titleElement =
        document.createElement(
            "strong"
        );


    titleElement.textContent =
        title;


    const descriptionElement =
        document.createElement(
            "p"
        );


    descriptionElement.textContent =
        description;


    content.appendChild(
        titleElement
    );


    content.appendChild(
        descriptionElement
    );


    finding.appendChild(
        statusElement
    );


    finding.appendChild(
        content
    );


    return finding;

}


/*
 * Run the basic security checks.
 */

function displaySecurityFindings(data) {

    securityFindings.innerHTML = "";


    /*
     * HTTPS check
     */

    if (!data.isHttps) {

        securityFindings.appendChild(
            createFinding(
                "!",
                "HTTPS is not enabled",
                "The current page is using an insecure HTTP connection.",
                "warning"
            )
        );

    } else {

        securityFindings.appendChild(
            createFinding(
                "✓",
                "HTTPS is enabled",
                "The current page is using HTTPS.",
                "safe"
            )
        );

    }


    /*
     * Password form check
     */

    if (data.passwordForms > 0) {

        if (data.isHttps) {

            securityFindings.appendChild(
                createFinding(
                    "i",
                    "Password form detected",
                    `${data.passwordForms} form(s) contain a password field. The page is using HTTPS.`,
                    "info"
                )
            );

        } else {

            securityFindings.appendChild(
                createFinding(
                    "!",
                    "Password form on HTTP page",
                    `${data.passwordForms} form(s) contain password fields while the page is not using HTTPS.`,
                    "warning"
                )
            );

        }

    }


    /*
     * Insecure form submission check
     */

    if (
        data.insecureForms.length > 0
    ) {

        securityFindings.appendChild(
            createFinding(
                "!",
                "Insecure form submission",
                `${data.insecureForms.length} form(s) submit data to an HTTP address.`,
                "warning"
            )
        );

    }


    /*
     * Mixed content check
     */

    if (
        data.mixedContent.length > 0
    ) {

        securityFindings.appendChild(
            createFinding(
                "!",
                "Mixed content detected",
                `${data.mixedContent.length} HTTP resource(s) were found on an HTTPS page.`,
                "warning"
            )
        );

    }


    /*
     * Content Security Policy check
     */

    if (data.hasCsp) {

        securityFindings.appendChild(
            createFinding(
                "✓",
                "CSP meta tag detected",
                "A Content Security Policy is declared through a meta tag.",
                "safe"
            )
        );

    } else {

        securityFindings.appendChild(
            createFinding(
                "i",
                "No CSP meta tag detected",
                "FlyGuard did not find a Content Security Policy declared through a meta tag.",
                "info"
            )
        );

    }


    /*
     * Inline script check
     */

    if (
        data.inlineScripts > 0
    ) {

        securityFindings.appendChild(
            createFinding(
                "i",
                "Inline scripts detected",
                `${data.inlineScripts} inline script(s) were found on the page.`,
                "info"
            )
        );

    }


    /*
     * External script information
     */

    if (
        data.externalScripts > 0
    ) {

        securityFindings.appendChild(
            createFinding(
                "i",
                "External scripts detected",
                `${data.externalScripts} external JavaScript file(s) were found.`,
                "info"
            )
        );

    }

}


/*
 * Display security headers.
 */

function displaySecurityHeaders(headers) {

    securityHeaders.innerHTML = "";


    const items = [

        {
            name:
                "X-Frame-Options",

            value:
                headers.xFrameOptions
        },

        {
            name:
                "X-Content-Type-Options",

            value:
                headers.contentTypeOptions
        },

        {
            name:
                "Referrer-Policy",

            value:
                headers.referrerPolicy
        },

        {
            name:
                "Permissions-Policy",

            value:
                headers.permissionsPolicy
        }

    ];


    items.forEach(item => {

        const row =
            document.createElement(
                "div"
            );


        row.className =
            "header-item";


        const name =
            document.createElement(
                "span"
            );


        name.textContent =
            item.name;


        const value =
            document.createElement(
                "strong"
            );


        value.textContent =
            item.value;


        row.appendChild(
            name
        );


        row.appendChild(
            value
        );


        securityHeaders.appendChild(
            row
        );

    });

}


/*
 * Display cookie information.
 */

function displayCookieStatus(count) {

    cookieStatus.textContent =
        count === 0
            ? "No accessible cookies detected"
            : `${count} accessible cookie${
                count === 1
                    ? ""
                    : "s"
            } detected`;

}


/*
 * Analyze the currently active tab.
 */

async function analyzeCurrentPage() {

    scanButton.disabled = true;


    buttonText.textContent =
        "Analyzing...";


    showMessage(
        "Analyzing current page..."
    );


    try {

        const tabs =
            await chrome.tabs.query({

                active: true,

                currentWindow: true

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


        /*
         * Chrome internal pages cannot
         * be analyzed using this method.
         */

        if (
            !activeTab.url ||
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
            await chrome.scripting
                .executeScript({

                    target: {
                        tabId:
                            activeTab.id
                    },

                    func:
                        analyzePage

                });


        if (
            !results ||
            !results[0] ||
            !results[0].result
        ) {

            throw new Error(
                "No analysis data returned."
            );

        }


        const data =
            results[0].result;


        displayResults(
            data
        );


        showMessage(
            "Analysis completed."
        );


    } catch (error) {

        console.error(
            "FlyGuard analysis error:",
            error
        );


        showMessage(
            error.message
        );


    } finally {

        buttonText.textContent =
            "Analyze Again";


        scanButton.disabled =
            false;

    }

}


scanButton.addEventListener(
    "click",
    analyzeCurrentPage
);


analyzeCurrentPage();