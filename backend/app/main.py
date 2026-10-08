import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import create_tables, get_connection
from .schemas import ScanRequest


app = FastAPI(
    title="FlyGuard API",
    description="Backend API for FlyGuard web security analysis.",
    version="0.3.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


create_tables()


@app.get("/")
def root():
    return {
        "name": "FlyGuard API",
        "version": "0.3.0",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/api/scans")
def create_scan(scan: ScanRequest):

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO scans (
            domain,
            url,
            protocol,
            is_https,

            links,
            scripts,
            images,
            forms,
            iframes,
            resources,

            third_party_domains,

            password_fields,
            insecure_forms,
            mixed_content,

            inline_scripts,
            external_scripts,

            has_csp,
            cookie_count,

            headers
        )
        VALUES (
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?
        )
        """,
        (
            scan.domain,
            scan.url,
            scan.protocol,
            int(scan.is_https),

            scan.links,
            scan.scripts,
            scan.images,
            scan.forms,
            scan.iframes,
            scan.resources,

            json.dumps(
                scan.third_party_domains
            ),

            scan.password_fields,
            scan.insecure_forms,
            int(scan.mixed_content),

            scan.inline_scripts,
            scan.external_scripts,

            int(scan.has_csp),
            scan.cookie_count,

            json.dumps(scan.headers)
        )
    )

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return {
        "message": "Scan saved",
        "scan_id": scan_id,
        "domain": scan.domain,
        "url": scan.url
    }


@app.get("/api/scans")
def get_scans(
    limit: int = 10,
    offset: int = 0
):
    if limit < 1:
        limit = 1

    if limit > 100:
        limit = 100

    if offset < 0:
        offset = 0

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            domain,
            url,
            protocol,
            is_https,

            links,
            scripts,
            images,
            forms,
            iframes,
            resources,

            third_party_domains,

            password_fields,
            insecure_forms,
            mixed_content,

            inline_scripts,
            external_scripts,

            has_csp,
            cookie_count,

            headers,

            created_at

        FROM scans

        ORDER BY id DESC

        LIMIT ? OFFSET ?
        """,
        (limit, offset)
    ).fetchall()

    connection.close()

    scans = []

    for row in rows:

        scan = dict(row)

        scan["is_https"] = bool(
            scan["is_https"]
        )

        scan["mixed_content"] = bool(
            scan["mixed_content"]
        )

        scan["has_csp"] = bool(
            scan["has_csp"]
        )

        scan["third_party_domains"] = json.loads(
            scan["third_party_domains"]
        )

        scan["headers"] = json.loads(
            scan["headers"]
        )

        scans.append(scan)

    return {
        "count": len(scans),
        "limit": limit,
        "offset": offset,
        "scans": scans
    }