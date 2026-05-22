from fastapi import APIRouter, Query, HTTPException
from db import get_pool
from datetime import datetime, timedelta, timezone

router = APIRouter()


@router.get("")
async def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(None, regex="^(low|medium|high|critical)$"),
    attack_type: str | None = None,
    since_minutes: int | None = Query(None, ge=1, le=10080),
):
    """List alerts with optional filtering."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        clauses = []
        params = []
        if severity:
            params.append(severity)
            clauses.append(f"severity = ${len(params)}")
        if attack_type:
            params.append(attack_type)
            clauses.append(f"attack_type = ${len(params)}")
        if since_minutes is not None:
            params.append(timedelta(minutes=since_minutes))
            clauses.append(f"timestamp > NOW() - ${len(params)}::interval")

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        total = await conn.fetchval(f"SELECT COUNT(*) FROM alerts {where}", *params)

        params.extend([limit, offset])
        rows = await conn.fetch(
            f"""
            SELECT
                id::text, timestamp, flow_id::text,
                severity, attack_type,
                confidence::float,
                src_ip::text, dst_ip::text,
                description, status
            FROM alerts
            {where}
            ORDER BY timestamp DESC
            LIMIT ${len(params)-1} OFFSET ${len(params)}
            """,
            *params,
        )

        items = []
        for row in rows:
            d = dict(row)
            d["timestamp"] = d["timestamp"].isoformat()
            if d["src_ip"]:
                d["src_ip"] = d["src_ip"].split("/")[0]
            if d["dst_ip"]:
                d["dst_ip"] = d["dst_ip"].split("/")[0]
            items.append(d)

        return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{alert_id}")
async def get_alert(alert_id: str):
    """Get full alert details including raw features."""
    import json  # add this if json isn't already imported at the top
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                id::text, timestamp, flow_id::text,
                severity, attack_type,
                confidence::float,
                src_ip::text, dst_ip::text,
                description, status, raw_features
            FROM alerts
            WHERE id = $1::uuid
            """,
            alert_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        d = dict(row)
        d["timestamp"] = d["timestamp"].isoformat()
        if d["src_ip"]:
            d["src_ip"] = d["src_ip"].split("/")[0]
        if d["dst_ip"]:
            d["dst_ip"] = d["dst_ip"].split("/")[0]
        # asyncpg returns JSONB as a string; parse it before returning
        if isinstance(d.get("raw_features"), str):
            d["raw_features"] = json.loads(d["raw_features"])
        return d


@router.get("/stats/summary")
async def alert_stats(since_minutes: int = Query(60, ge=1, le=10080)):
    """Summary stats for dashboard — total, by attack type, by severity, distinct IPs."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        interval = timedelta(minutes=since_minutes)
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE timestamp > NOW() - $1::interval",
            interval,
        )
        by_attack = await conn.fetch(
            """
            SELECT attack_type, COUNT(*) as count
            FROM alerts
            WHERE timestamp > NOW() - $1::interval
            GROUP BY attack_type ORDER BY count DESC
            """,
            interval,
        )
        by_severity = await conn.fetch(
            """
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp > NOW() - $1::interval
            GROUP BY severity ORDER BY
              CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
              END
            """,
            interval,
        )
        distinct_ips = await conn.fetchval(
            "SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE timestamp > NOW() - $1::interval",
            interval,
        )

    return {
        "since_minutes": since_minutes,
        "total": total,
        "distinct_source_ips": distinct_ips,
        "by_attack_type": [dict(r) for r in by_attack],
        "by_severity": [dict(r) for r in by_severity],
    }
