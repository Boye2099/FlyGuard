# FlyGuard

FlyGuard is a Chrome extension I’m building to quickly inspect the security and privacy signals of a webpage.

The idea is simple: instead of manually checking different parts of a website, FlyGuard brings useful information into one small interface.

## What it checks

FlyGuard currently looks at things like:

* HTTPS usage
* Password fields and forms
* Insecure form submissions
* Mixed content
* Inline and external JavaScript
* Content Security Policy
* Security headers
* Third-party domains and resources
* Accessible browser cookies
* Basic page and resource information

It also shows the results in a simple dashboard so the information is easier to understand.

## How it works

FlyGuard runs inside the browser and uses Chrome Extension APIs to inspect the active webpage.

The current version is built with:

* JavaScript
* HTML
* CSS
* Chrome Extension APIs

The security analysis currently runs on the webpage itself, while the popup handles displaying the results.

## Project Structure

```text
FlyGuard/
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── style.css
└── .gitignore
```

## Current Status

FlyGuard is still being developed.

The current focus is building the core security analysis engine first before adding more advanced features.

Planned improvements include:

* Security scoring
* Scan history
* FastAPI REST backend
* Database integration
* Extension-to-API communication
* Dashboard and reporting
* Docker support
* More advanced security analysis

## Why I built it

I wanted to build something that combines my interest in cybersecurity with practical software development.

Rather than making a collection of small security scripts, I wanted FlyGuard to grow into a proper application with a browser extension, backend, API, and eventually a more complete security analysis workflow.

## Disclaimer

FlyGuard is an educational security analysis tool. Its findings are indicators that can help with basic inspection and should not be treated as a complete security assessment of a website.
