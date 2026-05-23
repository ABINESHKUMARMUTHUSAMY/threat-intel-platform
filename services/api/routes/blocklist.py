from fastapi import APIRouter, Query, HTTPException
from db import get_pool
from datetime import timedelta

router = APIRouter()


@router.get("")
async def list_blocklist(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    active_only: bool = Query(False),
):
    """List blocklist entries with optional active-only filter."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        where = "WHERE active = true" if active_only else ""
        total = await conn.fetchval(f"SELECT COUNT(*) FROM blocklist {where}")
        rows = await conn.fetch(
            f"""
            SELECT id::text, ip_address::text, reason,
                   blocked_at, expires_at, alert_id::text, active
            FROM blocklist
            {where}
            ORDER BY blocked_at DESC
            LIMIT $1 OFFSET $2
            """,
            limit, offset,
        )
        items = []
        for row in rows:
            d = dict(row)
            d["blocked_at"] = d["blocked_at"].isoformat() if d["blocked_at"] else None
            d["expires_at"] = d["expires_at"].isoformat() if d["expires_at"] else None
            if d["ip_address"]:
                d["ip_address"] = d["ip_address"].split("/")[0]
            items.append(d)
        return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/stats/summary")
async def blocklist_stats():
    """Counts for dashboard: total ever, currently active, expired today, distinct IPs."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE active = true) AS active_blocks,
                COUNT(*) FILTER (WHERE active = false) AS inactive_blocks,
                COUNT(DISTINCT ip_address) AS distinct_ips_blocked,
                COUNT(*) FILTER (
                    WHERE active = false
                    AND expires_at IS NOT NULL
                    AND expires_at > NOW() - INTERVAL '24 hours'
                ) AS expired_24h
            FROM blocklist
            """
        )
    return dict(row)
