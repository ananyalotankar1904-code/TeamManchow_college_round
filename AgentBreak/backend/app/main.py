from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from app.core.config import settings
from app.api import agents, scans, findings, reports, traces, fixloop
from app.database.connection import engine, Base

# Create tables for initial setup
Base.metadata.create_all(bind=engine)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.get("/health")
def health_check():
    return {"status": "ok", "project": settings.PROJECT_NAME}

app.include_router(agents.router, prefix=f"{settings.API_V1_STR}/agents", tags=["agents"])
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(findings.router, prefix=f"{settings.API_V1_STR}/findings", tags=["findings"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
app.include_router(traces.router, prefix=f"{settings.API_V1_STR}/traces", tags=["traces"])
app.include_router(fixloop.router, prefix=f"{settings.API_V1_STR}/fixloop", tags=["fixloop"])
