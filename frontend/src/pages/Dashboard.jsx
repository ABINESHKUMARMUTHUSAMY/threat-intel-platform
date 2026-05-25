import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  BarChart, Bar, PieChart, Pie, Cell,
} from 'recharts'
import { AlertTriangle, ShieldAlert, Activity, CheckCircle2 } from 'lucide-react'
import { api } from '@/lib/api'

const OPERATOR_IP = '195.252.220.178'

const TIME_RANGES = [
  { label: '24 hours', minutes: 1440, bucket: 60 },
  { label: '7 days', minutes: 10080, bucket: 360 },
]

const SEVERITY_COLORS = {
  critical: '#7f1d1d',
  high: '#dc2626',
  medium: '#f59e0b',
  low: '#10b981',
}

const ATTACK_TYPE_COLORS = {
  PortScan: '#dc2626',
  DoS: '#f59e0b',
  Bruteforce: '#7c3aed',
  AnomalyUnknown: '#6b7280',
  WebAttack: '#0891b2',
  Botnet: '#be123c',
}

function buildParams(filters, extra = {}) {
  const p = new URLSearchParams()
  p.set('since_minutes', String(filters.minutes))
  if (filters.excludeOperator) p.set('exclude_operator_ip', OPERATOR_IP)
  for (const [k, v] of Object.entries(extra)) p.set(k, String(v))
  return p
}

function fetchAlertStats(filters) {
  return api.get(`/alerts/stats/summary?since_minutes=${filters.minutes}`).then(r => r.data)
}

function fetchPlaybookStats(filters) {
  return api.get(`/playbook-runs/stats/summary?since_minutes=${filters.minutes}`).then(r => r.data)
}

function fetchBlocklistStats() {
  return api.get('/blocklist/stats/summary').then(r => r.data)
}

function fetchTimeseries(filters) {
  const p = buildParams(filters, { bucket_minutes: filters.bucket })
  return api.get(`/alerts/stats/timeseries?${p}`).then(r => r.data)
}

function fetchTopTalkers(filters) {
  const p = buildParams(filters, { limit: 5 })
  return api.get(`/alerts/stats/top-talkers?${p}`).then(r => r.data)
}

function fetchRecentAlerts(filters) {
  const p = new URLSearchParams({ limit: '8', since_minutes: String(filters.minutes) })
  return api.get(`/alerts?${p}`).then(r => r.data)
}

export default function Dashboard() {
  const [filters, setFilters] = useState({
    minutes: 1440,
    bucket: 60,
    excludeOperator: true,
  })

  const alertStats = useQuery({
    queryKey: ['dashboard-alert-stats', filters.minutes],
    queryFn: () => fetchAlertStats(filters),
    refetchInterval: 10000,
  })
  const playbookStats = useQuery({
    queryKey: ['dashboard-playbook-stats', filters.minutes],
    queryFn: () => fetchPlaybookStats(filters),
    refetchInterval: 10000,
  })
  const blocklistStats = useQuery({
    queryKey: ['dashboard-blocklist-stats'],
    queryFn: fetchBlocklistStats,
    refetchInterval: 10000,
  })
  const timeseries = useQuery({
    queryKey: ['dashboard-timeseries', filters],
    queryFn: () => fetchTimeseries(filters),
    refetchInterval: 15000,
  })
  const topTalkers = useQuery({
    queryKey: ['dashboard-top-talkers', filters],
    queryFn: () => fetchTopTalkers(filters),
    refetchInterval: 15000,
  })
  const recentAlerts = useQuery({
    queryKey: ['dashboard-recent-alerts', filters.minutes],
    queryFn: () => fetchRecentAlerts(filters),
    refetchInterval: 5000,
  })

  const currentRange = TIME_RANGES.find(r => r.minutes === filters.minutes)

  return (
    <div className="p-8">
      <div className="flex items-end justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Dashboard</h2>
          <p className="text-sm text-muted-foreground">
            Real-time overview of detections, response actions, and active threats
          </p>
        </div>
        <FilterControls filters={filters} setFilters={setFilters} />
      </div>

      {/* Row 1: KPI tiles */}
      <div className="grid grid-cols-4 gap-3 mb-5">
        <KpiTile
          icon={AlertTriangle}
          label="Total alerts"
          value={alertStats.data?.total ?? '—'}
          sub={`${currentRange?.label || ''}`}
          accent="red"
        />
        <KpiTile
          icon={ShieldAlert}
          label="Active blocks"
          value={blocklistStats.data?.active_blocks ?? '—'}
          sub={`${blocklistStats.data?.distinct_ips_blocked ?? 0} distinct IPs ever`}
          accent={blocklistStats.data?.active_blocks > 0 ? 'red' : 'green'}
        />
        <KpiTile
          icon={Activity}
          label="Playbook runs"
          value={playbookStats.data?.total ?? '—'}
          sub={
            playbookStats.data
              ? `${playbookStats.data.succeeded}/${playbookStats.data.total} succeeded`
              : ''
          }
        />
        <KpiTile
          icon={CheckCircle2}
          label="Avg response time"
          value={playbookStats.data?.avg_duration_ms != null ? `${playbookStats.data.avg_duration_ms}ms` : '—'}
          sub={`max ${playbookStats.data?.max_duration_ms ?? 0}ms`}
          accent="green"
        />
      </div>

      {/* Row 2: Time series + Attack type distribution */}
      <div className="grid grid-cols-3 gap-3 mb-5">
        <ChartCard title="Alert volume over time" subtitle={`Per ${filters.bucket}min bucket, by detection source`} className="col-span-2">
          {timeseries.data && (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={timeseries.data.series} margin={{ top: 10, right: 20, bottom: 0, left: -10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis
                  dataKey="bucket"
                  tickFormatter={(t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  fontSize={11}
                />
                <YAxis fontSize={11} />
                <Tooltip
                  labelFormatter={(t) => new Date(t).toLocaleString()}
                  contentStyle={{ fontSize: 12 }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line type="monotone" dataKey="ml" stroke="#2563eb" strokeWidth={2} dot={false} name="ML" />
                <Line type="monotone" dataKey="suricata" stroke="#f59e0b" strokeWidth={2} dot={false} name="Suricata" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Attack types" subtitle={`${currentRange?.label}`}>
          {alertStats.data?.by_attack_type && (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={alertStats.data.by_attack_type}
                  dataKey="count"
                  nameKey="attack_type"
                  cx="50%" cy="50%"
                  innerRadius={50} outerRadius={90}
                  paddingAngle={2}
                >
                  {alertStats.data.by_attack_type.map((entry, i) => (
                    <Cell key={i} fill={ATTACK_TYPE_COLORS[entry.attack_type] || '#9ca3af'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} iconSize={10} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </div>

      {/* Row 3: Top talkers + Recent alerts */}
      <div className="grid grid-cols-2 gap-3">
        <ChartCard title="Top attacking IPs" subtitle={`${currentRange?.label}, by alert count`}>
          {topTalkers.data?.items && (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart
                data={topTalkers.data.items}
                layout="vertical"
                margin={{ top: 5, right: 10, bottom: 5, left: 100 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis type="number" fontSize={11} />
                <YAxis type="category" dataKey="src_ip" fontSize={11} width={120} />
                <Tooltip
                  contentStyle={{ fontSize: 12 }}
                  formatter={(v, n, p) => [
                    `${v} alerts (${p.payload.high_severity} high-severity)`,
                    'Count',
                  ]}
                />
                <Bar dataKey="alert_count" fill="#dc2626" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Recent alerts" subtitle="Last 8 alerts">
          <div className="text-sm">
            {recentAlerts.data?.items?.slice(0, 8).map(a => (
              <div key={a.id} className="flex items-center justify-between py-1.5 border-b border-border/40 last:border-b-0">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`inline-block w-2 h-2 rounded-full ${a.severity === 'high' || a.severity === 'critical' ? 'bg-red-500' : 'bg-amber-500'}`} />
                  <span className="font-mono text-xs truncate">{a.src_ip}</span>
                  <span className="text-xs text-muted-foreground">→</span>
                  <span className="text-xs">{a.attack_type}</span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {new Date(a.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
            {(!recentAlerts.data?.items || recentAlerts.data.items.length === 0) && (
              <div className="text-xs text-muted-foreground py-6 text-center">No alerts in this window.</div>
            )}
            <div className="text-right mt-2">
              <Link to="/alerts" className="text-xs text-blue-600 hover:underline">View all alerts →</Link>
            </div>
          </div>
        </ChartCard>
      </div>
    </div>
  )
}

function FilterControls({ filters, setFilters }) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <div className="flex border border-border rounded overflow-hidden">
        {TIME_RANGES.map(r => (
          <button
            key={r.minutes}
            onClick={() => setFilters({ ...filters, minutes: r.minutes, bucket: r.bucket })}
            className={`px-3 py-1 text-xs ${filters.minutes === r.minutes ? 'bg-secondary' : 'bg-background hover:bg-secondary/60'}`}
          >
            {r.label}
          </button>
        ))}
      </div>
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={filters.excludeOperator}
          onChange={(e) => setFilters({ ...filters, excludeOperator: e.target.checked })}
          className="rounded"
        />
        <span className="text-xs">Filter operator IP</span>
      </label>
    </div>
  )
}

function KpiTile({ icon: Icon, label, value, sub, accent }) {
  const accentBg = {
    red: 'bg-red-50',
    green: 'bg-emerald-50',
    yellow: 'bg-amber-50',
  }[accent] || 'bg-card'

  const accentIcon = {
    red: 'text-red-600',
    green: 'text-emerald-600',
    yellow: 'text-amber-600',
  }[accent] || 'text-muted-foreground'

  return (
    <div className={`border border-border rounded-md p-4 ${accentBg}`}>
      <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1.5">
        <Icon className={`w-3.5 h-3.5 ${accentIcon}`} />
        {label}
      </div>
      <div className="text-2xl font-semibold">{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </div>
  )
}

function ChartCard({ title, subtitle, children, className = '' }) {
  return (
    <div className={`border border-border rounded-md p-4 bg-card ${className}`}>
      <div className="mb-3">
        <div className="font-medium text-sm">{title}</div>
        {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
      </div>
      {children}
    </div>
  )
}
