from fastapi import APIRouter, Query, HTTPException
from db import get_pool
import json

router = APIRouter()


@router.get("")
async def list_playbook_runs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None, regex="^(running|success|failed)$"),
    playbook_name: str | None = None,
):
    """List playbook executions with optional status/name filtering."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        clauses = []
        params = []
        if status:
            params.append(status)
            clauses.append(f"pr.status = ${len(params)}")
        if playbook_name:
            params.append(playbook_name)
            clauses.append(f"pr.playbook_name = ${len(params)}")
        where = "WHERE " + " AND ".join(clauses) if clauses else ""

        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM playbook_runs pr {where}", *params,
        )

        params.extend([limit, offset])
        rows = await conn.fetch(
            f"""
            SELECT
                pr.id::text, pr.playbook_name, pr.status,
                pr.started_at, pr.completed_at, pr.duration_ms,
                pr.error_message,
                pr.alert_id::text,
                a.attack_type, a.severity,
                a.src_ip::text AS src_ip,
                a.dst_ip::text AS dst_ip
            FROM playbook_runs pr
            LEFT JOIN alerts a ON pr.alert_id = a.id
            {where}
            ORDER BY pr.started_at DESC
            LIMIT ${len(params)-1} OFFSET ${len(params)}
            """,
            *params,
        )
        items = []
        for row in rows:
            d = dict(row)
            d["started_at"] = d["started_at"].isoformat() if d["started_at"] else None
            d["completed_at"] = d["completed_at"].isoformat() if d["completed_at"] else None
            if d.get("src_ip"):
                d["src_ip"] = d["src_ip"].split("/")[0]
            if d.get("dst_ip"):
                d["dst_ip"] = d["dst_ip"].split("/")[0]
            items.append(d)
        return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{run_id}")
async def get_playbook_run(run_id: str):
    """Full playbook run details including the actions_taken JSONB."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                pr.id::text, pr.playbook_name, pr.status,
                pr.started_at, pr.completed_at, pr.duration_ms,
                pr.error_message, pr.actions_taken,
                pr.alert_id::text,
                a.attack_type, a.severity, a.confidence::float,
                a.src_ip::text AS src_ip, a.dst_ip::text AS dst_ip,
                a.description AS alert_description
            FROM playbook_runs pr
            LEFT JOIN alerts a ON pr.alert_id = a.id
            WHERE pr.id = $1::uuid
            """,
            run_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Playbook run not found")
        d = dict(row)
        d["started_at"] = d["started_at"].isoformat() if d["started_at"] else None
        d["completed_at"] = d["completed_at"].isoformat() if d["completed_at"] else None
        if d.get("src_ip"):
            d["src_ip"] = d["src_ip"].split("/")[0]
        if d.get("dst_ip"):
            d["dst_ip"] = d["dst_ip"].split("/")[0]
        # asyncpg returns JSONB as a string — parse it
        if isinstance(d.get("actions_taken"), str):
            d["actions_taken"] = json.loads(d["actions_taken"])
        return d


@router.get("/stats/summary")
async def playbook_stats(since_minutes: int = Query(60, ge=1, le=10080)):
    """Aggregate counts and timing stats over the lookback window."""
    pool = await get_pool()
    from datetime import timedelta
    async with pool.acquire() as conn:
        interval = timedelta(minutes=since_minutes)
        summary = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'success') AS succeeded,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE status = 'running') AS running,
                AVG(duration_ms)::int AS avg_duration_ms,
                MAX(duration_ms) AS max_duration_ms
            FROM playbook_runs
            WHERE started_at > NOW() - $1::interval
            """,
            interval,
        )
        by_playbook = await conn.fetch(
            """
            SELECT playbook_name, COUNT(*) AS count,
                   AVG(duration_ms)::int AS avg_duration_ms,
                   COUNT(*) FILTER (WHERE status = 'failed') AS failures
            FROM playbook_runs
            WHERE started_at > NOW() - $1::interval
            GROUP BY playbook_name
            ORDER BY count DESC
            """,
            interval,
        )
    return {
        "since_minutes": since_minutes,
        **dict(summary),
        "by_playbook": [dict(r) for r in by_playbook],
    }
