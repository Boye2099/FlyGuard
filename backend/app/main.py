from fastapi import FastAPI

from .schemas import ScanRequest


app = FastAPI(
    title="FlyGuard API",
    description="Backend API for FlyGuard web security analysis.",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "name": "FlyGuard API",
        "version": "0.1.0",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/api/scans")
def create_scan(scan: ScanRequest):
    return {
        "message": "Scan received",
        "domain": scan.domain,
        "url": scan.url
    }