"""Topology endpoints — passive network graph derived from flow records.

Edges are aggregated per (src_ip, dst_ip) so a single attacker→victim pair
becomes one edge with port-list metadata, rather than one edge per port.
This keeps the graph readable when an attacker performs port scans.

By default the response is filtered to "attack-relevant" edges only —
edges that involve the attacker IP or that look like a scan/heavy traffic.
This surfaces the demo story (attacker doing recon) while hiding routine
operational traffic (sensor talking to DHCP, DNS, NTP, etc.).

Active (nmap-based) scanning was prototyped but deferred — passive flow-derived
topology has stronger demo value, and active scanning of broad subnets inside
a container proved operationally brittle. The host_inventory and topology_scans
tables remain in the schema for future reactivation.
"""
from datetime import timedelta
from fastapi import APIRouter, Query
from db import get_pool
import logging
import os

log = logging.getLogger("api.topology")
router = APIRouter()

LAB_CIDR = os.getenv("LAB_CIDR", "10.20.0.0/16")
SENSOR_IP = os.getenv("SENSOR_PRIVATE_IP", "10.20.9.39")
ATTACKER_IP = os.getenv("ATTACKER_PRIVATE_IP", "10.20.7.205")
VICTIM_IP = os.getenv("VICTIM_PRIVATE_IP", "10.20.10.22")


def infer_role(ip: str, dst_ports: list) -> str:
    """Heuristic role inference from known hosts + observed port profile.

    For passive topology, dst_ports are the ports this host has been seen
    *receiving* traffic on — i.e., ports it's hosting services on.
    """
    if ip == SENSOR_IP:
        return "sensor"
    if ip == ATTACKER_IP:
        return "attacker"
    if ip == VICTIM_IP:
        return "victim"
    if any(p in dst_ports for p in (80, 443, 8080)):
        return "http_server"
    if 22 in dst_ports:
        return "ssh_server"
    if 53 in dst_ports:
        return "dns_server"
    return "unknown"


def classify_edge(unique_ports: int, total_flows: int) -> str:
    """Tag an edge based on its shape.

    - port_scan: many unique destination ports (fan-out behaviour)
    - heavy:     high total flow count
    - normal:    anything else
    """
    if unique_ports >= 20:
        return "port_scan"
    if total_flows >= 100:
        return "heavy"
    return "normal"


@router.get("/passive")
async def passive_topology(
    since_minutes: int = Query(60, ge=1, le=10080),
    include_external: bool = Query(False, description="Include traffic to/from outside the lab subnet"),
    min_flow_count: int = Query(3, ge=1, description="Minimum total flow count to include an edge"),
    attack_relevant_only: bool = Query(
        True,
        description="Only show edges involving the attacker or classified as port_scan/heavy",
    ),
):
    """Build a node-edge graph from the flows table over the recent window.

    Aggregates per (src_ip, dst_ip) pair so port-scan activity becomes a
    single annotated edge rather than one edge per probed port. By default,
    filters to "attack-relevant" edges (involving the attacker, or
    classified as scan/heavy) to keep the graph focused on the demo story.
    """
    pool = await get_pool()
    interval = timedelta(minutes=since_minutes)

    if include_external:
        lab_filter_sql = ""
    else:
        lab_filter_sql = f" AND src_ip << '{LAB_CIDR}'::inet AND dst_ip << '{LAB_CIDR}'::inet"

    async with pool.acquire() as conn:
        # CTE: per (src, dst, proto, port) flow counts and byte sums,
        # then aggregate per (src, dst) so each pair becomes a single edge.
        edges = await conn.fetch(
            f"""
            WITH per_port AS (
                SELECT
                    src_ip,
                    dst_ip,
                    protocol,
                    dst_port,
                    COUNT(*) AS pair_port_flow_count,
                    SUM(fwd_bytes + bwd_bytes) AS pair_port_bytes,
                    MAX(timestamp) AS last_seen
                FROM flows
                WHERE timestamp > NOW() - $1::interval
                  AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
                  {lab_filter_sql}
                GROUP BY src_ip, dst_ip, protocol, dst_port
            )
            SELECT
                src_ip::text AS src,
                dst_ip::text AS dst,
                COUNT(DISTINCT dst_port) AS unique_ports,
                SUM(pair_port_flow_count) AS total_flows,
                COALESCE(SUM(pair_port_bytes), 0) AS total_bytes,
                (ARRAY_AGG(DISTINCT dst_port ORDER BY dst_port))[1:50] AS dst_ports,
                ARRAY_AGG(DISTINCT protocol) AS protocols,
                MAX(last_seen) AS last_seen
            FROM per_port
            GROUP BY src_ip, dst_ip
            HAVING SUM(pair_port_flow_count) >= $2
            ORDER BY total_flows DESC
            LIMIT 100
            """,
            interval, min_flow_count,
        )

    def strip_cidr(ip):
        return ip.split("/")[0] if ip else ip

    # Filter to attack-relevant edges if requested
    if attack_relevant_only:
        def is_relevant(edge):
            src = strip_cidr(edge["src"])
            dst = strip_cidr(edge["dst"])
            if src == ATTACKER_IP or dst == ATTACKER_IP:
                return True
            unique_ports = int(edge["unique_ports"])
            total_flows = int(edge["total_flows"])
            if unique_ports >= 20 or total_flows >= 100:
                return True
            return False
        edges = [e for e in edges if is_relevant(e)]

    # Collect node IPs from the (possibly filtered) edges
    node_ips = set()
    for e in edges:
        node_ips.add(e["src"])
        node_ips.add(e["dst"])

    # Build a map of dst_ip -> set of dst_ports it has received traffic on,
    # excluding port 0 which is a TCP/UDP placeholder for malformed flows.
    ports_per_dst = {}
    for e in edges:
        dst = e["dst"]
        ports = [p for p in (e["dst_ports"] or []) if p and p != 0]
        ports_per_dst.setdefault(dst, set()).update(ports)

    nodes = []
    for ip_with_mask in node_ips:
        ip = strip_cidr(ip_with_mask)
        dst_ports_seen = sorted(ports_per_dst.get(ip_with_mask, set()))
        nodes.append({
            "id": ip,
            "ip": ip,
            "role": infer_role(ip, dst_ports_seen),
            "observed_dst_ports": dst_ports_seen[:20],
        })

    edge_list = []
    for e in edges:
        unique_ports = int(e["unique_ports"])
        total_flows = int(e["total_flows"])
        # Drop the bogus port-0 entries from the dst_ports list for display
        dst_ports = [p for p in (list(e["dst_ports"]) if e["dst_ports"] else []) if p and p != 0]
        edge_list.append({
            "source": strip_cidr(e["src"]),
            "target": strip_cidr(e["dst"]),
            "unique_ports": unique_ports,
            "total_flows": total_flows,
            "total_bytes": int(e["total_bytes"] or 0),
            "dst_ports": dst_ports,
            "protocols": list(e["protocols"]) if e["protocols"] else [],
            "classification": classify_edge(unique_ports, total_flows),
            "last_seen": e["last_seen"].isoformat() if e["last_seen"] else None,
        })

    return {
        "since_minutes": since_minutes,
        "include_external": include_external,
        "min_flow_count": min_flow_count,
        "attack_relevant_only": attack_relevant_only,
        "nodes": nodes,
        "edges": edge_list,
        "node_count": len(nodes),
        "edge_count": len(edge_list),
    }
