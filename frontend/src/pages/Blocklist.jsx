import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Ban, Clock } from 'lucide-react'
import { api } from '@/lib/api'

function fetchBlocklist(activeOnly) {
  const params = new URLSearchParams({ limit: '100' })
  if (activeOnly) params.set('active_only', 'true')
  return api.get(`/blocklist?${params}`).then(r => r.data)
}

function fetchStats() {
  return api.get('/blocklist/stats/summary').then(r => r.data)
}

function formatRelative(iso) {
  if (!iso) return '—'
  const now = new Date()
  const then = new Date(iso)
  const deltaS = Math.floor((then - now) / 1000)
  if (deltaS > 0) {
    const m = Math.floor(deltaS / 60)
    const s = deltaS % 60
    if (m > 0) return `in ${m}m ${s}s`
    return `in ${s}s`
  }
  const ago = -deltaS
  const m = Math.floor(ago / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function Blocklist() {
  const [activeOnly, setActiveOnly] = useState(false)

  const { data: blocklist, isLoading, isError } = useQuery({
    queryKey: ['blocklist', activeOnly],
    queryFn: () => fetchBlocklist(activeOnly),
    refetchInterval: 5000,
  })

  const { data: stats } = useQuery({
    queryKey: ['blocklist-stats'],
    queryFn: fetchStats,
    refetchInterval: 5000,
  })

  return (
    <div className="p-8">
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Blocklist</h2>
        <p className="text-sm text-muted-foreground">
          IPs currently and previously blocked by the response engine
          {blocklist && ` · ${blocklist.total} entries`}
        </p>
      </div>

      {stats && <StatsBar stats={stats} />}

      <div className="flex items-center gap-3 mb-4 text-sm">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => setActiveOnly(e.target.checked)}
            className="rounded"
          />
          <span className="text-xs">Show active only</span>
        </label>
      </div>

      {isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}
      {isError && <div className="text-sm text-destructive">Failed to load blocklist.</div>}

      {blocklist?.items && (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-secondary text-secondary-foreground text-xs">
              <tr>
                <Th>Status</Th>
                <Th>IP address</Th>
                <Th>Reason</Th>
                <Th>Blocked</Th>
                <Th>Expires</Th>
                <Th>Alert</Th>
              </tr>
            </thead>
            <tbody>
              {blocklist.items.map((b) => (
                <tr key={b.id} className="border-t border-border hover:bg-secondary/40">
                  <Td>
                    <StatusBadge active={b.active} expiresAt={b.expires_at} />
                  </Td>
                  <Td className="font-mono text-xs">{b.ip_address}</Td>
                  <Td className="text-xs">{b.reason || '—'}</Td>
                  <Td className="text-xs text-muted-foreground" title={b.blocked_at}>
                    {formatRelative(b.blocked_at)}
                  </Td>
                  <Td className="text-xs text-muted-foreground" title={b.expires_at}>
                    {b.expires_at ? formatRelative(b.expires_at) : 'no expiry'}
                  </Td>
                  <Td className="text-xs">
                    {b.alert_id ? (
                      <code className="text-muted-foreground">{b.alert_id.slice(0, 8)}</code>
                    ) : '—'}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
          {blocklist.items.length === 0 && (
            <div className="p-12 text-center">
              <Ban className="w-8 h-8 mx-auto mb-3 text-muted-foreground/50" />
              <div className="text-sm text-muted-foreground">No blocklist entries.</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatsBar({ stats }) {
  return (
    <div className="grid grid-cols-4 gap-3 mb-5">
      <StatCard label="Active blocks" value={stats.active_blocks} accent />
      <StatCard label="Distinct IPs" value={stats.distinct_ips_blocked} />
      <StatCard label="Expired (24h)" value={stats.expired_24h} />
      <StatCard label="Total entries" value={(stats.active_blocks || 0) + (stats.inactive_blocks || 0)} />
    </div>
  )
}

function StatCard({ label, value, accent = false }) {
  return (
    <div className={`border border-border rounded-md p-3 ${accent ? 'bg-red-50' : 'bg-card'}`}>
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className="text-lg font-semibold">{value ?? 0}</div>
    </div>
  )
}

function StatusBadge({ active, expiresAt }) {
  if (active) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium ring-1 ring-inset bg-red-100 text-red-800 ring-red-200">
        <Ban className="w-3 h-3" />
        Active
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium ring-1 ring-inset bg-slate-100 text-slate-700 ring-slate-200">
      <Clock className="w-3 h-3" />
      Expired
    </span>
  )
}

function Th({ children, align = 'left' }) {
  return <th className={`px-3 py-2 font-medium text-${align}`}>{children}</th>
}
function Td({ children, align = 'left', className = '' }) {
  return <td className={`px-3 py-2 text-${align} ${className}`}>{children}</td>
}
