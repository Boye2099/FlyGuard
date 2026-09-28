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


/*
    Analyze the current webpage.

    This function runs inside the webpage itself.
*/

async function analyzePage() {

    const currentURL =
        window.location.href;

    const currentOrigin =
        window.location.origin;

    const currentProtocol =
        window.location.protocol;


    /*
        BASIC PAGE INFORMATION
    */

    const links =
        document.querySelectorAll("a");

    const scripts =
        document.querySelectorAll("script");

    const images =
        document.querySelectorAll("img");

    const forms =
        document.querySelectorAll("form");

    const iframes =
        document.querySelectorAll("iframe");


    /*
        RESOURCE ANALYSIS
    */

    const resourceElements =
        document.querySelectorAll(
            "script[src], img[src], iframe[src], link[href]"
        );


    /*
        THIRD-PARTY DOMAINS
    */

    const thirdPartySet =
        new Set();


    resourceElements.forEach(element => {

        const resourceURL =
            element.src ||
            element.href;

        if (!resourceURL) {
            return;
        }

        try {

            const parsedURL =
                new URL(
                    resourceURL,
                    currentURL
                );

            if (
                parsedURL.hostname &&
                parsedURL.hostname !==
                window.location.hostname
            ) {

                thirdPartySet.add(
                    parsedURL.hostname
                );

            }

        } catch (error) {

            console.log(
                "Could not parse resource:",
                error
            );

        }

    });


    /*
        PAGE SIZE
    */

    const pageHTML =
        document.documentElement.outerHTML;

    const pageBlob =
        new Blob([pageHTML]);

    const pageSizeBytes =
        pageBlob.size;


    function formatBytes(bytes) {

        if (bytes === 0) {
            return "0 Bytes";
        }

        const units = [
            "Bytes",
            "KB",
            "MB"
        ];

        const index =
            Math.floor(
                Math.log(bytes) /
                Math.log(1024)
            );

        return (
            parseFloat(
                (
                    bytes /
                    Math.pow(
                        1024,
                        index
                    )
                ).toFixed(2)
            ) +
            " " +
            units[index]
        );

    }


    /*
        HTTPS CHECK
    */

    const isHTTPS =
        currentProtocol === "https:";


    /*
        PASSWORD FORM CHECK
    */

    const passwordInputs =
        document.querySelectorAll(
            'input[type="password"]'
        );

    const hasPasswordForm =
        passwordInputs.length > 0;


    /*
        INSECURE FORM CHECK
    */

    let insecureForms = 0;

    forms.forEach(form => {

        const action =
            form.getAttribute("action");

        if (!action) {
            return;
        }

        try {

            const formURL =
                new URL(
                    action,
                    currentURL
                );

            if (
                isHTTPS &&
                formURL.protocol === "http:"
            ) {

                insecureForms++;

            }

        } catch (error) {

            console.log(
                "Could not analyze form:",
                error
            );

        }

    });


    /*
        MIXED CONTENT CHECK
    */

    let mixedContent = 0;

    if (isHTTPS) {

        resourceElements.forEach(element => {

            const resourceURL =
                element.src ||
                element.href;

            if (!resourceURL) {
                return;
            }

            try {

                const parsedURL =
                    new URL(
                        resourceURL,
                        currentURL
                    );

                if (
                    parsedURL.protocol ===
                    "http:"
                ) {

                    mixedContent++;

                }

            } catch (error) {

                console.log(
                    "Could not analyze mixed content:",
                    error
                );

            }

        });

    }


    /*
        INLINE SCRIPT CHECK
    */

    const inlineScripts =
        document.querySelectorAll(
            "script:not([src])"
        );

    const hasInlineScripts =
        inlineScripts.length > 0;


    /*
        EXTERNAL JAVASCRIPT CHECK
    */

    const externalScripts =
        document.querySelectorAll(
            "script[src]"
        );

    const hasExternalScripts =
        externalScripts.length > 0;


    /*
        CSP META CHECK
    */

    const cspMeta =
        document.querySelector(
            'meta[http-equiv="Content-Security-Policy"]'
        );

    const hasCSP =
        cspMeta !== null;


    /*
        COOKIE CHECK

        document.cookie only exposes cookies
        accessible to JavaScript.

        HttpOnly cookies are not included.
    */

    const cookies =
        document.cookie;

    const cookieCount =
        cookies
            ? cookies.split(";").length
            : 0;


    /*
        SECURITY HEADER CHECK

        This attempts to retrieve the response
        headers for the current page.
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
                ) ||
                "Not detected",


            contentTypeOptions:
                response.headers.get(
                    "X-Content-Type-Options"
                ) ||
                "Not detected",


            referrerPolicy:
                response.headers.get(
                    "Referrer-Policy"
                ) ||
                "Not detected",


            permissionsPolicy:
                response.headers.get(
                    "Permissions-Policy"
                ) ||
                "Not detected"

        };

    } catch (error) {

        console.log(
            "Could not inspect response headers:",
            error
        );

    }


    /*
        RETURN EVERYTHING TO THE EXTENSION
    */

    return {

        domain:
            window.location.hostname,

        url:
            currentURL,

        origin:
            currentOrigin,

        protocol:
            currentProtocol,

        isHTTPS:
            isHTTPS,

        title:
            document.title,

        pageSize:
            formatBytes(
                pageSizeBytes
            ),

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
            resourceElements.length,

        thirdPartyDomains:
            Array.from(
                thirdPartySet
            ),

        hasPasswordForm:
            hasPasswordForm,

        insecureForms:
            insecureForms,

        mixedContent:
            mixedContent,

        hasInlineScripts:
            hasInlineScripts,

        hasExternalScripts:
            hasExternalScripts,

        hasCSP:
            hasCSP,

        headers:
            headerResults,

        cookieCount:
            cookieCount

    };

}


/*
    Display all analysis results.
*/

function displayResults(data) {

    domain.textContent =
        data.domain ||
        "Unknown";

    url.textContent =
        data.url ||
        "Unknown";

    protocol.textContent =
        data.protocol ||
        "-";

    pageTitle.textContent =
        data.title ||
        "Untitled";

    pageSize.textContent =
        data.pageSize ||
        "0 Bytes";

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


    /*
        HTTPS STATUS
    */

    httpsStatus.textContent =
        data.isHTTPS
            ? "HTTPS"
            : "HTTP";


    /*
        SECURITY STATUS
    */

    message.textContent =
        "Analysis completed";


    /*
        THIRD-PARTY DOMAINS
    */

    displayThirdPartyDomains(
        data.thirdPartyDomains
    );


    /*
        SECURITY FINDINGS
    */

    displaySecurityFindings(
        data
    );


    /*
        SECURITY HEADERS
    */

    displaySecurityHeaders(
        data.headers
    );


    /*
        COOKIES
    */

    displayCookieStatus(
        data.cookieCount
    );

}


/*
    Display third-party domains.
*/

function displayThirdPartyDomains(
    domains
) {

    thirdPartyDomains.innerHTML = "";


    if (
        !domains ||
        domains.length === 0
    ) {

        const empty =
            document.createElement("span");

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
            document.createElement("div");

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
    Display security findings.
*/

function displaySecurityFindings(
    data
) {

    securityFindings.innerHTML = "";


    function addFinding(
        type,
        icon,
        title,
        description
    ) {

        const finding =
            document.createElement("div");

        finding.className =
            `finding ${type}`;


        const status =
            document.createElement("span");

        status.className =
            "finding-status";

        status.textContent =
            icon;


        const content =
            document.createElement("div");


        const heading =
            document.createElement("strong");

        heading.textContent =
            title;


        const text =
            document.createElement("p");

        text.textContent =
            description;


        content.appendChild(
            heading
        );

        content.appendChild(
            text
        );


        finding.appendChild(
            status
        );

        finding.appendChild(
            content
        );


        securityFindings.appendChild(
            finding
        );

    }


    /*
        HTTPS
    */

    if (data.isHTTPS) {

        addFinding(
            "safe",
            "✓",
            "HTTPS enabled",
            "The page is using an encrypted HTTPS connection."
        );

    } else {

        addFinding(
            "warning",
            "!",
            "HTTPS not enabled",
            "The page is using HTTP instead of HTTPS."
        );

    }


    /*
        PASSWORD FORMS
    */

    if (data.hasPasswordForm) {

        addFinding(
            "info",
            "i",
            "Password field detected",
            "This page contains a password input field."
        );

    }


    /*
        INSECURE FORMS
    */

    if (data.insecureForms > 0) {

        addFinding(
            "warning",
            "!",
            "Insecure form submission",
            `${data.insecureForms} form${
                data.insecureForms === 1
                    ? ""
                    : "s"
            } submit over HTTP.`
        );

    }


    /*
        MIXED CONTENT
    */

    if (data.mixedContent > 0) {

        addFinding(
            "warning",
            "!",
            "Mixed content detected",
            `${data.mixedContent} resource${
                data.mixedContent === 1
                    ? ""
                    : "s"
            } load over HTTP.`
        );

    }


    /*
        INLINE SCRIPTS
    */

    if (data.hasInlineScripts) {

        addFinding(
            "info",
            "i",
            "Inline scripts detected",
            "The page contains JavaScript embedded directly in the HTML."
        );

    }


    /*
        EXTERNAL JAVASCRIPT
    */

    if (data.hasExternalScripts) {

        addFinding(
            "info",
            "i",
            "External JavaScript detected",
            "The page loads JavaScript from external script resources."
        );

    }


    /*
        CSP
    */

    if (data.hasCSP) {

        addFinding(
            "safe",
            "✓",
            "CSP detected",
            "A Content Security Policy meta tag was found."
        );

    } else {

        addFinding(
            "neutral",
            "-",
            "CSP not detected",
            "No Content Security Policy meta tag was found."
        );

    }


    /*
        THIRD-PARTY RESOURCES
    */

    if (
        data.thirdPartyDomains &&
        data.thirdPartyDomains.length > 0
    ) {

        addFinding(
            "info",
            "i",
            "Third-party resources detected",
            `${data.thirdPartyDomains.length} third-party domain${
                data.thirdPartyDomains.length === 1
                    ? ""
                    : "s"
            } were found.`
        );

    }


    /*
        DEFAULT MESSAGE
    */

    if (
        securityFindings.children.length === 0
    ) {

        addFinding(
            "neutral",
            "-",
            "No findings",
            "No security signals were detected."
        );

    }

}


/*
    Display security headers.
*/

function displaySecurityHeaders(
    headers
) {

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
            document.createElement("div");

        row.className =
            "header-item";


        const name =
            document.createElement("span");

        name.textContent =
            item.name;


        const value =
            document.createElement("strong");

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
    Display cookie information.
*/

function displayCookieStatus(
    count
) {

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
    Analyze the active browser tab.
*/

async function analyzeCurrentPage() {

    buttonText.textContent =
        "Analyzing...";

    scanButton.disabled =
        true;

    message.textContent =
        "Analyzing current page...";


    try {

        const tabs =
            await chrome.tabs.query({
                active: true,
                currentWindow: true
            });


        const activeTab =
            tabs[0];


        if (!activeTab) {

            throw new Error(
                "No active tab found."
            );

        }


        /*
            Chrome internal pages cannot
            be analyzed by the extension.
        */

        if (
            activeTab.url &&
            (
                activeTab.url.startsWith(
                    "chrome://"
                ) ||
                activeTab.url.startsWith(
                    "chrome-extension://"
                )
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


        if (
            !results ||
            !results[0] ||
            !results[0].result
        ) {

            throw new Error(
                "No analysis result returned."
            );

        }


        const data =
            results[0].result;


        displayResults(
            data
        );


    } catch (error) {

        console.error(
            "FlyGuard analysis error:",
            error
        );


        message.textContent =
            error.message ||
            "Could not analyze this page.";

    } finally {

        buttonText.textContent =
            "Analyze Page";

        scanButton.disabled =
            false;

    }

}


/*
    Analyze when the button is clicked.
*/

scanButton.addEventListener(
    "click",
    analyzeCurrentPage
);


/*
    Automatically analyze the page
    when the popup opens.
*/

analyzeCurrentPage();