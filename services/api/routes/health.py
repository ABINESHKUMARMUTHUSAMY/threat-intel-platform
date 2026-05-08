from fastapi import APIRouter, HTTPException
import redis.asyncio as redis

from config import settings
from db import get_pool

router = APIRouter()


@router.get("/health")
async def health():
    checks = {"api": "ok", "postgres": "unknown", "redis": "unknown"}
    overall_ok = True

    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {e}"
        overall_ok = False

    try:
        r = redis.Redis(host=settings.redis_host, port=settings.redis_port)
        if await r.ping():
            checks["redis"] = "ok"
        await r.close()
    except Exception as e:
        checks["redis"] = f"error: {e}"
        overall_ok = False

    if not overall_ok:
        raise HTTPException(status_code=503, detail=checks)

    return checks
