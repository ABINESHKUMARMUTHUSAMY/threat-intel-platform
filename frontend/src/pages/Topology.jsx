import { useState, useRef, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import ForceGraph2D from 'react-force-graph-2d'
import { Network, ShieldAlert, Server, HelpCircle, Crosshair } from 'lucide-react'
import { api } from '@/lib/api'

const TIME_RANGES = [
  { label: 'Last hour', value: 60 },
  { label: 'Last 6 hours', value: 360 },
  { label: 'Last 24 hours', value: 1440 },
  { label: 'Last 7 days', value: 10080 },
]

// Role → color and icon
const ROLE_STYLES = {
  attacker:    { color: '#dc2626', label: 'Attacker',    icon: Crosshair },
  victim:      { color: '#f59e0b', label: 'Victim',      icon: ShieldAlert },
  sensor:      { color: '#2563eb', label: 'Sensor',      icon: Server },
  http_server: { color: '#16a34a', label: 'HTTP server', icon: Server },
  ssh_server:  { color: '#0891b2', label: 'SSH server',  icon: Server },
  dns_server:  { color: '#7c3aed', label: 'DNS server',  icon: Server },
  unknown:     { color: '#6b7280', label: 'Unknown',     icon: HelpCircle },
}

// Edge classification → color and width
const EDGE_STYLES = {
  port_scan: { color: '#dc2626', width: 3, label: 'Port scan' },
  heavy:     { color: '#f59e0b', width: 2, label: 'Heavy' },
  normal:    { color: '#9ca3af', width: 1, label: 'Normal' },
}

function fetchTopology({ since_minutes, attack_relevant_only }) {
  const params = new URLSearchParams()
  params.set('since_minutes', String(since_minutes))
  params.set('min_flow_count', '3')
  params.set('attack_relevant_only', String(attack_relevant_only))
  return api.get(`/topology/passive?${params}`).then(r => r.data)
}

export default function Topology() {
  const [filters, setFilters] = useState({
    since_minutes: 1440,
    attack_relevant_only: true,
  })
  const [selectedNode, setSelectedNode] = useState(null)
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 })
  const containerRef = useRef(null)
  const fgRef = useRef(null)

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['topology', filters],
    queryFn: () => fetchTopology(filters),
    refetchInterval: 10000,
  })

  // Track container size for the canvas
  useEffect(() => {
    if (!containerRef.current) return
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        setDimensions({ width, height })
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  // Graph data — copy because react-force-graph mutates node positions
  const graphData = data
    ? {
        nodes: data.nodes.map(n => ({ ...n })),
        links: data.edges.map(e => ({ ...e })),
      }
    : { nodes: [], links: [] }

  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node)
    if (fgRef.current) {
      fgRef.current.centerAt(node.x, node.y, 600)
      fgRef.current.zoom(2.5, 600)
    }
  }, [])

  return (
    <div className="p-8 h-full flex flex-col">
      <div className="mb-4">
        <h2 className="text-2xl font-semibold mb-1">Network topology</h2>
        <p className="text-sm text-muted-foreground">
          Host-to-host relationships derived from captured flow data
          {data && ` · ${data.node_count} hosts, ${data.edge_count} connections`}
        </p>
      </div>

      <FilterBar filters={filters} setFilters={setFilters} onRefresh={refetch} />

      <Legend />

      <div className="flex gap-4 flex-1 min-h-0">
        <div
          ref={containerRef}
          className="flex-1 border border-border rounded-md bg-card relative overflow-hidden"
          style={{ minHeight: 500 }}
        >
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground">
              Loading topology...
            </div>
          )}
          {isError && (
            <div className="absolute inset-0 flex items-center justify-center text-sm text-destructive">
              Failed to load topology.
            </div>
          )}
          {!isLoading && graphData.nodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
              <Network className="w-12 h-12 text-muted-foreground/40" />
              <div className="text-sm text-muted-foreground">No traffic in this window.</div>
            </div>
          )}
          {dimensions.width > 0 && graphData.nodes.length > 0 && (
            <ForceGraph2D
              ref={fgRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}
              nodeId="id"
              nodeLabel={(n) => `${n.ip} (${ROLE_STYLES[n.role]?.label || n.role})`}
              nodeRelSize={8}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const style = ROLE_STYLES[node.role] || ROLE_STYLES.unknown
                const label = node.ip
                const fontSize = 12 / globalScale
                const radius = 10

                // Node circle
                ctx.fillStyle = style.color
                ctx.beginPath()
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false)
                ctx.fill()

                // Border (selected highlight)
                if (selectedNode && selectedNode.id === node.id) {
                  ctx.strokeStyle = '#000'
                  ctx.lineWidth = 2 / globalScale
                  ctx.stroke()
                }

                // Label below
                ctx.font = `${fontSize}px ui-sans-serif, system-ui`
                ctx.fillStyle = '#111'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'top'
                ctx.fillText(label, node.x, node.y + radius + 2)
              }}
              nodePointerAreaPaint={(node, color, ctx) => {
                ctx.fillStyle = color
                ctx.beginPath()
                ctx.arc(node.x, node.y, 12, 0, 2 * Math.PI, false)
                ctx.fill()
              }}
              linkSource="source"
              linkTarget="target"
              linkColor={(link) => (EDGE_STYLES[link.classification] || EDGE_STYLES.normal).color}
              linkWidth={(link) => (EDGE_STYLES[link.classification] || EDGE_STYLES.normal).width}
              linkLabel={(link) => `${link.unique_ports} ports · ${link.total_flows} flows · ${(EDGE_STYLES[link.classification] || EDGE_STYLES.normal).label}`}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={1}
              linkDirectionalParticles={(link) => (link.classification === 'port_scan' ? 4 : 0)}
              linkDirectionalParticleSpeed={0.006}
              linkDirectionalParticleWidth={2}
              onNodeClick={handleNodeClick}
              onBackgroundClick={() => setSelectedNode(null)}
              cooldownTicks={100}
            />
          )}
        </div>

        <NodeDetailPanel node={selectedNode} edges={data?.edges || []} onClose={() => setSelectedNode(null)} />
      </div>
    </div>
  )
}

function FilterBar({ filters, setFilters, onRefresh }) {
  return (
    <div className="flex items-center gap-3 mb-3 text-sm">
      <label className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">Time:</span>
        <select
          value={filters.since_minutes}
          onChange={(e) => setFilters({ ...filters, since_minutes: Number(e.target.value) })}
          className="px-2 py-1 text-xs border border-border rounded bg-background"
        >
          {TIME_RANGES.map(t => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={filters.attack_relevant_only}
          onChange={(e) => setFilters({ ...filters, attack_relevant_only: e.target.checked })}
          className="rounded"
        />
        <span className="text-xs">Attack-relevant only</span>
      </label>
      <button
        onClick={onRefresh}
        className="px-3 py-1 text-xs border border-border rounded bg-background hover:bg-secondary"
      >
        Refresh
      </button>
    </div>
  )
}

function Legend() {
  return (
    <div className="flex items-center gap-4 mb-3 text-xs text-muted-foreground">
      <span>Roles:</span>
      {Object.entries(ROLE_STYLES).filter(([k]) => k !== 'unknown').map(([k, s]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: s.color }} />
          {s.label}
        </span>
      ))}
      <span className="ml-3">Edges:</span>
      {Object.entries(EDGE_STYLES).map(([k, s]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="inline-block w-6 h-0.5" style={{ background: s.color, height: s.width }} />
          {s.label}
        </span>
      ))}
    </div>
  )
}

function NodeDetailPanel({ node, edges, onClose }) {
  if (!node) return null

  // Find edges involving this node
  const incoming = edges.filter(e => e.target === node.ip)
  const outgoing = edges.filter(e => e.source === node.ip)

  return (
    <div className="w-80 border border-border rounded-md bg-card p-4 overflow-auto">
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <div className="text-xs text-muted-foreground uppercase tracking-wide">
            {ROLE_STYLES[node.role]?.label || node.role}
          </div>
          <div className="font-mono text-lg">{node.ip}</div>
        </div>
        <button onClick={onClose} className="text-xs text-muted-foreground hover:text-foreground">
          Close
        </button>
      </div>

      {node.observed_dst_ports && node.observed_dst_ports.length > 0 && (
        <Section label="Observed listening ports">
          <div className="font-mono text-xs flex flex-wrap gap-1">
            {node.observed_dst_ports.map(p => (
              <span key={p} className="px-1.5 py-0.5 bg-secondary rounded">{p}</span>
            ))}
          </div>
        </Section>
      )}

      {outgoing.length > 0 && (
        <Section label={`Outbound (${outgoing.length})`}>
          {outgoing.map((e, i) => (
            <EdgeSummary key={i} edge={e} otherSide={e.target} />
          ))}
        </Section>
      )}

      {incoming.length > 0 && (
        <Section label={`Inbound (${incoming.length})`}>
          {incoming.map((e, i) => (
            <EdgeSummary key={i} edge={e} otherSide={e.source} />
          ))}
        </Section>
      )}

      {incoming.length === 0 && outgoing.length === 0 && (
        <div className="text-xs text-muted-foreground">No edges for this node in the current view.</div>
      )}
    </div>
  )
}

function EdgeSummary({ edge, otherSide }) {
  const style = EDGE_STYLES[edge.classification] || EDGE_STYLES.normal
  return (
    <div className="text-xs py-1.5 border-b border-border/40 last:border-b-0">
      <div className="flex items-baseline justify-between">
        <span className="font-mono">{otherSide}</span>
        <span className="px-1.5 py-0.5 rounded text-white text-[10px]" style={{ background: style.color }}>
          {style.label}
        </span>
      </div>
      <div className="text-muted-foreground mt-0.5">
        {edge.unique_ports} ports · {edge.total_flows} flows · {(edge.protocols || []).join(', ')}
      </div>
    </div>
  )
}

function Section({ label, children }) {
  return (
    <div className="mb-4">
      <div className="text-xs uppercase tracking-wide text-muted-foreground mb-1.5">{label}</div>
      {children}
    </div>
  )
}
