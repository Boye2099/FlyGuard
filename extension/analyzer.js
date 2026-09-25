/**
 * FlyGuard
 * Webpage reconnaissance engine
 *
 * This function runs inside the active webpage.
 * It collects information from the DOM and returns
 * a structured result to the extension popup.
 */

function analyzePage() {

    const currentOrigin = window.location.origin;

    const currentHostname = window.location.hostname;


    /*
     * Convert a resource URL into a hostname.
     *
     * Example:
     *
     * https://cdn.example.com/script.js
     *
     * becomes:
     *
     * cdn.example.com
     */

    function getHostname(url) {

        try {

            return new URL(url, window.location.href).hostname;

        } catch {

            return null;

        }

    }


    /*
     * Collect external resources.
     */

    const resources = [
        ...document.querySelectorAll("script[src]"),
        ...document.querySelectorAll("img[src]"),
        ...document.querySelectorAll("iframe[src]"),
        ...document.querySelectorAll("link[href]")
    ];


    /*
     * Find unique domains used by external resources.
     */

    const thirdPartyDomains = new Set();


    resources.forEach(resource => {

        const source =
            resource.src ||
            resource.href;

        if (!source) {
            return;
        }

        const hostname = getHostname(source);

        if (
            hostname &&
            hostname !== currentHostname
        ) {

            thirdPartyDomains.add(hostname);

        }

    });


    /*
     * Calculate the approximate HTML document size.
     */

    const pageSize =
        new Blob([
            document.documentElement.outerHTML
        ]).size;


    /*
     * Return structured analysis data.
     */

    return {

        title: document.title || "Untitled",

        hostname: currentHostname,

        origin: currentOrigin,

        protocol: window.location.protocol.replace(":", ""),

        isHttps:
            window.location.protocol === "https:",

        pageSize,

        links:
            document.querySelectorAll("a").length,

        scripts:
            document.querySelectorAll("script").length,

        images:
            document.querySelectorAll("img").length,

        forms:
            document.querySelectorAll("form").length,

        iframes:
            document.querySelectorAll("iframe").length,

        externalResources:
            resources.length,

        thirdPartyDomains:
            Array.from(thirdPartyDomains).sort()

    };

}