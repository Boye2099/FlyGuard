const websiteElement = document.getElementById("website");
const scanButton = document.getElementById("scanButton");
const messageElement = document.getElementById("message");


// Get information about the currently active Chrome tab
chrome.tabs.query(
    { active: true, currentWindow: true },
    function (tabs) {

        const currentTab = tabs[0];

        if (!currentTab || !currentTab.url) {
            websiteElement.textContent = "Unable to detect website";
            return;
        }

        try {
            const url = new URL(currentTab.url);

            websiteElement.textContent = url.hostname;

        } catch (error) {

            websiteElement.textContent = "Unknown website";

        }
    }
);


// Handle the scan button
scanButton.addEventListener("click", function () {

    messageElement.textContent = "Scanner coming in Day 2...";

});