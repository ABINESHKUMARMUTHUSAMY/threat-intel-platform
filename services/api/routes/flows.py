from fastapi import APIRouter, Query
from db import get_pool

router = APIRouter()


@router.get("")
async def list_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Build dynamic WHERE clause
        clauses = []
        params = []
        if src_ip:
            params.append(src_ip)
            clauses.append(f"src_ip = ${len(params)}::inet")
        if dst_ip:
            params.append(dst_ip)
            clauses.append(f"dst_ip = ${len(params)}::inet")
        if protocol:
            params.append(protocol.upper())
            clauses.append(f"protocol = ${len(params)}")

        where = "WHERE " + " AND ".join(clauses) if clauses else ""

        count_row = await conn.fetchval(f"SELECT COUNT(*) FROM flows {where}", *params)

        params.extend([limit, offset])
        rows = await conn.fetch(
            f"""
            SELECT
                id, timestamp, src_ip::text, dst_ip::text,
                src_port, dst_port, protocol, duration_ms,
                fwd_packet_count, bwd_packet_count,
                fwd_bytes, bwd_bytes,
                syn_count, ack_count, fin_count, rst_count,
                psh_count, urg_count,
                iat_mean_ms, pkt_len_mean
            FROM flows
            {where}
            ORDER BY timestamp DESC
            LIMIT ${len(params)-1} OFFSET ${len(params)}
            """,
            *params,
        )

        items = [dict(row) for row in rows]
        # Convert datetimes and numerics for JSON
        for item in items:
            item["timestamp"] = item["timestamp"].isoformat()
            item["id"] = str(item["id"])
            if item["iat_mean_ms"] is not None:
                item["iat_mean_ms"] = float(item["iat_mean_ms"])
            if item["pkt_len_mean"] is not None:
                item["pkt_len_mean"] = float(item["pkt_len_mean"])

    return {"items": items, "total": count_row, "limit": limit, "offset": offset}
