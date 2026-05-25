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
    detection_source: str | None = Query(None, regex="^(ml|suricata|manual)$"), 

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
        if detection_source:
            params.append(detection_source)
            clauses.append(f"detection_source = ${len(params)}")
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
                description, status,
        	detection_source
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
                description, status, raw_features,
        	detection_source
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
@router.get("/stats/timeseries")
async def alert_timeseries(
    since_minutes: int = Query(60, ge=1, le=10080),
    bucket_minutes: int = Query(1, ge=1, le=1440, description="Time bucket size in minutes"),
    exclude_operator_ip: str | None = Query(None, description="src_ip to exclude (e.g. operator's laptop)"),
):
    """Alert counts bucketed over time, separated by detection_source."""
    pool = await get_pool()
    from datetime import timedelta
    interval = timedelta(minutes=since_minutes)
    bucket = timedelta(minutes=bucket_minutes)

    extra_filter = ""
    params = [interval, bucket]
    if exclude_operator_ip:
        params.append(exclude_operator_ip)
        extra_filter = f" AND src_ip != ${len(params)}::inet"

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            WITH all_buckets AS (
                SELECT generate_series(
                    time_bucket($2::interval, NOW() - $1::interval),
                    time_bucket($2::interval, NOW()),
                    $2::interval
                ) AS bucket
            ),
            alert_counts AS (
                SELECT
                    time_bucket($2::interval, timestamp) AS bucket,
                    detection_source,
                    COUNT(*) AS count
                FROM alerts
                WHERE timestamp > NOW() - $1::interval
                  {extra_filter}
                GROUP BY bucket, detection_source
            )
            SELECT
                ab.bucket,
                ac.detection_source,
                COALESCE(ac.count, 0) AS count
            FROM all_buckets ab
            LEFT JOIN alert_counts ac ON ab.bucket = ac.bucket
            ORDER BY ab.bucket ASC
            """,
            *params,
        )

    # Pivot to: [{bucket, ml, suricata}] for easier frontend consumption
    by_bucket = {}
    for r in rows:
        b = r["bucket"].isoformat()
        if b not in by_bucket:
            by_bucket[b] = {"bucket": b, "ml": 0, "suricata": 0, "total": 0}
        if r["detection_source"] is None:
            continue
        by_bucket[b][r["detection_source"]] = r["count"]
        by_bucket[b]["total"] += r["count"]

    return {
        "since_minutes": since_minutes,
        "bucket_minutes": bucket_minutes,
        "series": list(by_bucket.values()),
    }
@router.get("/stats/top-talkers")
async def alert_top_talkers(
    since_minutes: int = Query(1440, ge=1, le=10080),
    limit: int = Query(10, ge=1, le=50),
    exclude_operator_ip: str | None = Query(None),
):
    """Top source IPs by alert count over the window."""
    pool = await get_pool()
    from datetime import timedelta
    interval = timedelta(minutes=since_minutes)

    extra_filter = ""
    params = [interval, limit]
    if exclude_operator_ip:
        params.append(exclude_operator_ip)
        extra_filter = f" AND src_ip != ${len(params)}::inet"

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT
                src_ip::text AS src_ip,
                COUNT(*) AS alert_count,
                COUNT(*) FILTER (WHERE severity = 'high' OR severity = 'critical') AS high_severity,
                MAX(timestamp) AS last_seen,
                ARRAY_AGG(DISTINCT attack_type ORDER BY attack_type) AS attack_types
            FROM alerts
            WHERE timestamp > NOW() - $1::interval
              {extra_filter}
            GROUP BY src_ip
            ORDER BY alert_count DESC
            LIMIT $2
            """,
            *params,
        )

    items = []
    for r in rows:
        d = dict(r)
        d["src_ip"] = d["src_ip"].split("/")[0]
        d["last_seen"] = d["last_seen"].isoformat() if d["last_seen"] else None
        d["attack_types"] = list(d["attack_types"]) if d["attack_types"] else []
        items.append(d)
    return {"since_minutes": since_minutes, "items": items}
