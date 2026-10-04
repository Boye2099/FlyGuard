# FlyGuard

FlyGuard is a web security analysis tool I'm building as a Chrome extension.

It gives me a quick way to inspect the security signals behind a webpage, from HTTPS and security headers to forms, scripts, cookies, and third-party resources.

I'm also building a FastAPI backend around it, so the project is gradually becoming more than just a browser extension.

## What it does

* Checks HTTPS
* Finds password fields and insecure forms
* Detects mixed content
* Checks for CSP and security headers
* Looks at inline and external scripts
* Identifies third-party domains
* Checks accessible cookies
* Collects basic page information
* Calculates a security score
* Keeps recent scan history
* Sends scan data to the backend

## Built with

**Extension**

* JavaScript
* HTML
* CSS
* Chrome Extension APIs

**Backend**

* Python
* FastAPI
* Pydantic
* Uvicorn

## Structure

```text
FlyGuard/
├── extension/
│   ├── analyzer.js
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── style.css
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   └── schemas.py
│   ├── requirements.txt
│   └── .gitignore
│
├── .gitignore
└── README.md
```

## How it works

FlyGuard analyzes the active webpage, collects the available security signals, calculates a score, and displays the results in the extension.

```text
Webpage
   ↓
Analyzer
   ↓
Security analysis
   ↓
Score + findings
   ↓
Local history
   ↓
FastAPI backend
```

The browser handles the initial analysis while the backend is being built out to handle storage and future processing.

## Backend

Run the API locally with:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app
```

API:

```text
http://127.0.0.1:8000
```

Docs:

```text
http://127.0.0.1:8000/docs
```

Current endpoints:

```text
GET  /
GET  /health
POST /api/scans
```

## Security score

FlyGuard starts each scan at 100 and applies deductions when it finds things like:

* Missing HTTPS
* Insecure forms
* Mixed content
* Password fields on non-HTTPS pages
* Missing CSP
* Missing security headers

The score is meant to give a quick picture of what FlyGuard found. It isn't a replacement for a proper security assessment.

## What's next

* More security checks
* Database storage
* Better API functionality
* Authentication
* Dashboard
* Automated threat detection
* Tests
* Docker

## Why FlyGuard?

I'm building FlyGuard to get deeper into web security while working with browser APIs, JavaScript, backend development, and REST APIs.

It's a project I'm building from the ground up and improving as I learn more.

## Disclaimer

FlyGuard is an educational security project and is not a replacement for a professional security assessment or penetration test.
