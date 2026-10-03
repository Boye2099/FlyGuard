# FlyGuard

FlyGuard is a web security tool I'm building as a Chrome extension.

It analyzes the page you're currently on and gives you a quick look at things like HTTPS, security headers, forms, scripts, cookies, third-party resources, and other security signals.

I'm also building a FastAPI backend for it, so the project is gradually moving from a browser extension into a proper security analysis system.

## What it does

* Checks HTTPS
* Detects password fields
* Finds insecure form submissions
* Checks for mixed content
* Looks for inline and external scripts
* Checks for CSP and security headers
* Finds third-party domains
* Checks accessible cookies
* Collects basic page information
* Calculates a security score
* Keeps recent scan history locally

## Stack

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

## Project structure

```text
FlyGuard/
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── style.css
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── schemas.py
│   │   └── __init__.py
│   └── requirements.txt
│
├── .gitignore
└── README.md
```

## Backend

The API is currently running locally with FastAPI.

Start it with:

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

The extension and API aren't connected yet. That's the next part I'm working on.

## What's next

* Connect the extension to the API
* Add database storage
* Improve the security checks
* Add authentication
* Build a dashboard
* Add automated threat detection
* Dockerize the backend
* Add tests

## Why FlyGuard?

I'm building FlyGuard to get more hands-on with web security, backend development, APIs, and the systems that connect them.

It's still a work in progress, but each version is adding another part of the system.

## Disclaimer

FlyGuard is an educational security project and is not a replacement for a full security assessment or penetration test.
