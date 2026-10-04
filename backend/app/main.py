from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .schemas import ScanRequest


app = FastAPI(
    title="FlyGuard API",
    description="Backend API for FlyGuard web security analysis.",
    version="0.2.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "FlyGuard API",
        "version": "0.2.0",
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