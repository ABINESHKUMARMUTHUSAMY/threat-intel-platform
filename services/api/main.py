from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from db import get_pool, close_pool
from routes import alerts, flows, assets, blocklist, incidents, health, playbook_runs, topology


@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()
    yield
    await close_pool()


app = FastAPI(
    title="Threat Intel Platform API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["health"])
app.include_router(flows.router, prefix="/flows", tags=["flows"])
app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(blocklist.router, prefix="/blocklist", tags=["blocklist"])
app.include_router(playbook_runs.router, prefix="/playbook-runs", tags=["playbook-runs"])
app.include_router(topology.router, prefix="/topology", tags=["topology"])


@app.get("/")
async def root():
    return {"service": "threat-intel-api", "version": "0.1.0", "docs": "/docs"}
