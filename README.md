# FlyGuard

FlyGuard is a Chrome extension I'm building to inspect the security and privacy signals of webpages.

The idea is simple: instead of manually checking different parts of a website, FlyGuard brings useful security information into one place and gives a quick overview of what it finds.

## What it currently checks

FlyGuard currently analyzes:

- HTTPS usage
- Password fields
- Insecure form submissions
- Mixed content
- Inline JavaScript
- External JavaScript
- Content Security Policy
- Security response headers
- Third-party domains and resources
- Accessible browser cookies
- Basic page and resource information

It also calculates a security score based on the signals it can currently inspect.

## Scan History

FlyGuard stores the five most recent scans locally using Chrome's Storage API.

Each saved scan contains:

- Domain
- Security score
- Scan timestamp

The history remains available when the extension popup is closed and reopened.

## How it works

FlyGuard runs as a Chrome Extension and uses Chrome Extension APIs to inspect the active webpage.

The current architecture is:

```text
Chrome Extension
│
├── popup.html
├── style.css
└── popup.js
       │
       ├── Webpage analysis
       ├── Security checks
       ├── Security scoring
       └── Local scan history
              │
              ▼
       chrome.storage.local