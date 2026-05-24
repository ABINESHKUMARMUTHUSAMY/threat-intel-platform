import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle } from 'lucide-react'
import { api } from '@/lib/api'
import { SeverityBadge } from '@/lib/severity'
import AlertDetailModal from '@/components/AlertDetailModal'

const ATTACK_TYPES = ['', 'PortScan', 'Bruteforce', 'DoS', 'WebAttack', 'Botnet', 'AnomalyUnknown']
const SEVERITIES = ['', 'low', 'medium', 'high', 'critical']
const TIME_RANGES = [
  { label: 'Last 15 min', value: 15 },
  { label: 'Last hour', value: 60 },
  { label: 'Last 24 hours', value: 1440 },
  { label: 'Last 7 days', value: 10080 },
]

function fetchAlerts(filters) {
  const params = new URLSearchParams()
  params.set('limit', '100')
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.attack_type) params.set('attack_type', filters.attack_type)
  if (filters.detection_source) params.set('detection_source', filters.detection_source) 
  if (filters.since_minutes) params.set('since_minutes', filters.since_minutes)
  return api.get(`/alerts?${params}`).then(r => r.data)
}

function fetchStats(sinceMinutes) {
  return api.get(`/alerts/stats/summary?since_minutes=${sinceMinutes}`).then(r => r.data)
}

export default function Alerts() {
  const [filters, setFilters] = useState({ severity: '', attack_type: '', detection_source: '', since_minutes: 60 })
  const [selectedAlertId, setSelectedAlertId] = useState(null)

  const { data: alerts, isLoading, isError } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => fetchAlerts(filters),
    refetchInterval: 5000,
  })

  const { data: stats } = useQuery({
    queryKey: ['alert-stats', filters.since_minutes],
    queryFn: () => fetchStats(filters.since_minutes),
    refetchInterval: 5000,
  })

  return (
    <div className="p-8">
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Alerts</h2>
        <p className="text-sm text-muted-foreground">
          Detected threats from XGBoost classifier and Isolation Forest anomaly channel
          {alerts && ` · ${alerts.total} matching`}
        </p>
      </div>

      {stats && <StatsBar stats={stats} />}

      <FilterBar filters={filters} setFilters={setFilters} />

      {isLoading && (
        <div className="text-sm text-muted-foreground">Loading...</div>
      )}
      {isError && (
        <div className="text-sm text-destructive">Failed to load alerts.</div>
      )}

      {alerts?.items && (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-secondary text-secondary-foreground text-xs">
              <tr>
                <Th>Time</Th>
                <Th>Severity</Th>
                <Th>Source</Th>
                <Th>Attack type</Th>
                <Th>Source IP</Th>
                <Th>Destination</Th>
                <Th align="right">Confidence</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody>
              {alerts.items.map((a) => (
                <tr
                  key={a.id}
                  className="border-t border-border hover:bg-secondary/40 cursor-pointer"
                  onClick={() => setSelectedAlertId(a.id)}
                >
                  <Td>{new Date(a.timestamp).toLocaleTimeString()}</Td>
                  <Td><SeverityBadge severity={a.severity} /></Td>
                  <Td><DetectionSourceBadge source={a.detection_source} /></Td>
          <Td className="font-medium">{a.attack_type}</Td>
                  <Td className="font-mono text-xs">{a.src_ip}</Td>
                  <Td className="font-mono text-xs">{a.dst_ip}</Td>
                  <Td align="right" className="font-mono text-xs">
                    {(a.confidence * 100).toFixed(1)}%
                  </Td>
                  <Td className="text-xs text-muted-foreground">{a.status}</Td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.items.length === 0 && (
            <div className="p-12 text-center">
              <AlertTriangle className="w-8 h-8 mx-auto mb-3 text-muted-foreground/50" />
              <div className="text-sm text-muted-foreground">
                No alerts matching the current filters.
              </div>
            </div>
          )}
        </div>
      )}

      <AlertDetailModal alertId={selectedAlertId} onClose={() => setSelectedAlertId(null)} />
    </div>
  )
}

function DetectionSourceBadge({ source }) {
  const styles = {
    ml: 'bg-blue-100 text-blue-800 ring-blue-200',
    suricata: 'bg-amber-100 text-amber-800 ring-amber-200',
    manual: 'bg-slate-100 text-slate-700 ring-slate-200',
  }
  const labels = {
    ml: 'ML',
    suricata: 'SURICATA',
    manual: 'MANUAL',
  }
  const style = styles[source] || styles.manual
  const label = labels[source] || (source ? source.toUpperCase() : '—')
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ring-1 ring-inset ${style}`}>
      {label}
    </span>
  )
}
function StatsBar({ stats }) {
  return (
    <div className="grid grid-cols-4 gap-3 mb-5">
      <StatCard label="Total alerts" value={stats.total} />
      <StatCard label="Distinct sources" value={stats.distinct_source_ips} />
      <StatCard
        label="Top attack"
        value={stats.by_attack_type[0]?.attack_type || '—'}
        sub={stats.by_attack_type[0] ? `${stats.by_attack_type[0].count} alerts` : ''}
      />
      <StatCard
        label="Highest severity"
        value={stats.by_severity[0]?.severity || '—'}
        sub={stats.by_severity[0] ? `${stats.by_severity[0].count} alerts` : ''}
      />
    </div>
  )
}

function StatCard({ label, value, sub }) {
  return (
    <div className="border border-border rounded-md p-3 bg-card">
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className="text-lg font-semibold capitalize">{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-0.5">{sub}</div>}
    </div>
  )
}

function FilterBar({ filters, setFilters }) {
  return (
    <div className="flex items-center gap-3 mb-4 text-sm">
      <Select
        label="Severity"
        value={filters.severity}
        onChange={(v) => setFilters({ ...filters, severity: v })}
        options={SEVERITIES.map(s => ({ value: s, label: s || 'All' }))}
      />
      <Select
        label="Attack type"
        value={filters.attack_type}
        onChange={(v) => setFilters({ ...filters, attack_type: v })}
        options={ATTACK_TYPES.map(s => ({ value: s, label: s || 'All' }))}
      />
      <Select
    label="Detection Source"
      value={filters.detection_source}
      onChange={(v) => setFilters({ ...filters, detection_source: v })}
        options={[
          { value: '', label: 'All sources' },
          { value: 'ml', label: 'ML' },
          { value: 'suricata', label: 'Suricata' },
        ]}
      />
      <Select
        label="Time range"
        value={filters.since_minutes}
        onChange={(v) => setFilters({ ...filters, since_minutes: Number(v) })}
        options={TIME_RANGES.map(t => ({ value: t.value, label: t.label }))}
      />
    </div>
  )
}

function Select({ label, value, onChange, options }) {
  return (
    <label className="flex items-center gap-2">
      <span className="text-xs text-muted-foreground">{label}:</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-2 py-1 text-xs border border-border rounded bg-background"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="capitalize">
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}

function Th({ children, align = 'left' }) {
  return <th className={`px-3 py-2 font-medium text-${align}`}>{children}</th>
}
function Td({ children, align = 'left', className = '' }) {
  return <td className={`px-3 py-2 text-${align} ${className}`}>{children}</td>
}
