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

const scanButton =
    document.getElementById("scanButton");

const buttonText =
    document.getElementById("buttonText");

const message =
    document.getElementById("message");


/*
 * Convert bytes into a readable size.
 */

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


/*
 * Display a status message.
 */

function showMessage(text) {

    message.textContent = text;

}


/*
 * This function runs inside the webpage
 * being analyzed.
 */

function analyzePage() {

    const hostname =
        window.location.hostname;


    /*
     * Collect resources loaded by
     * the webpage.
     */

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


    /*
     * Store unique third-party domains.
     */

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


            /*
             * If the resource belongs
             * to another hostname,
             * consider it third-party.
             */

            if (
                resourceURL.hostname &&
                resourceURL.hostname !== hostname
            ) {

                thirdPartyDomains.add(
                    resourceURL.hostname
                );

            }

        } catch {

            /*
             * Ignore malformed URLs.
             */

        }

    });


    /*
     * Estimate the size of the
     * current HTML document.
     */

    const pageSize =
        new Blob([
            document.documentElement
                .outerHTML
        ]).size;


    /*
     * Return the collected information.
     */

    return {

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
            ).sort()

    };

}


/*
 * Display the analysis results
 * inside the popup.
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


    /*
     * Clear previous third-party
     * domain results.
     */

    thirdPartyDomains.innerHTML = "";


    /*
     * If there are no third-party
     * domains, show a message.
     */

    if (
        data.thirdPartyDomains.length === 0
    ) {

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


    /*
     * Display each third-party domain.
     */

    data.thirdPartyDomains.forEach(
        domainName => {

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

        }
    );

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

        /*
         * Find the active browser tab.
         */

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
         * Chrome system pages cannot
         * be analyzed.
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


        /*
         * Execute analyzePage()
         * inside the active webpage.
         */

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


        /*
         * Make sure Chrome returned
         * analysis data.
         */

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


        /*
         * Put the results into
         * the popup.
         */

        displayResults(data);


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


/*
 * Run analysis when the button
 * is clicked.
 */

scanButton.addEventListener(
    "click",
    analyzeCurrentPage
);


/*
 * Automatically analyze the
 * current page when the popup opens.
 */

analyzeCurrentPage();