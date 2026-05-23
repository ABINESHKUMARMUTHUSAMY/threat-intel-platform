import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, XCircle, Loader2, Play } from 'lucide-react'
import { api } from '@/lib/api'
import PlaybookRunDetailModal from '@/components/PlaybookRunDetailModal'

const STATUSES = ['', 'running', 'success', 'failed']

function fetchRuns(filters) {
  const params = new URLSearchParams({ limit: '100' })
  if (filters.status) params.set('status', filters.status)
  if (filters.playbook_name) params.set('playbook_name', filters.playbook_name)
  return api.get(`/playbook-runs?${params}`).then(r => r.data)
}

function fetchStats() {
  return api.get('/playbook-runs/stats/summary?since_minutes=1440').then(r => r.data)
}

export default function PlaybookRuns() {
  const [filters, setFilters] = useState({ status: '', playbook_name: '' })
  const [selectedRunId, setSelectedRunId] = useState(null)

  const { data: runs, isLoading } = useQuery({
    queryKey: ['playbook-runs', filters],
    queryFn: () => fetchRuns(filters),
    refetchInterval: 5000,
  })

  const { data: stats } = useQuery({
    queryKey: ['playbook-stats'],
    queryFn: fetchStats,
    refetchInterval: 5000,
  })

  const playbookNames = stats?.by_playbook?.map(p => p.playbook_name) || []

  return (
    <div className="p-8">
      <div className="mb-6">
        <h2 className="text-2xl font-semibold mb-1">Playbook runs</h2>
        <p className="text-sm text-muted-foreground">
          Audit log of every action the response engine has taken
          {runs && ` · ${runs.total} total`}
        </p>
      </div>

      {stats && <StatsBar stats={stats} />}

      <div className="flex items-center gap-3 mb-4 text-sm">
        <Select
          label="Status"
          value={filters.status}
          onChange={(v) => setFilters({ ...filters, status: v })}
          options={STATUSES.map(s => ({ value: s, label: s || 'All' }))}
        />
        <Select
          label="Playbook"
          value={filters.playbook_name}
          onChange={(v) => setFilters({ ...filters, playbook_name: v })}
          options={[{ value: '', label: 'All' }, ...playbookNames.map(p => ({ value: p, label: p }))]}
        />
      </div>

      {isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}

      {runs?.items && (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-secondary text-secondary-foreground text-xs">
              <tr>
                <Th>Time</Th>
                <Th>Status</Th>
                <Th>Playbook</Th>
                <Th>Triggered by</Th>
                <Th>Source</Th>
                <Th align="right">Duration</Th>
              </tr>
            </thead>
            <tbody>
              {runs.items.map((r) => (
                <tr
                  key={r.id}
                  className="border-t border-border hover:bg-secondary/40 cursor-pointer"
                  onClick={() => setSelectedRunId(r.id)}
                >
                  <Td className="text-xs">{new Date(r.started_at).toLocaleTimeString()}</Td>
                  <Td><RunStatusBadge status={r.status} /></Td>
                  <Td className="font-medium">{r.playbook_name}</Td>
                  <Td className="text-xs">
                    {r.attack_type || <span className="text-muted-foreground">—</span>}
                  </Td>
                  <Td className="font-mono text-xs">{r.src_ip || '—'}</Td>
                  <Td align="right" className="text-xs">
                    {r.duration_ms != null ? `${r.duration_ms}ms` : '—'}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
          {runs.items.length === 0 && (
            <div className="p-12 text-center">
              <Play className="w-8 h-8 mx-auto mb-3 text-muted-foreground/50" />
              <div className="text-sm text-muted-foreground">No playbook runs yet.</div>
            </div>
          )}
        </div>
      )}

      <PlaybookRunDetailModal runId={selectedRunId} onClose={() => setSelectedRunId(null)} />
    </div>
  )
}

function StatsBar({ stats }) {
  return (
    <div className="grid grid-cols-4 gap-3 mb-5">
      <StatCard label="Total (24h)" value={stats.total ?? 0} />
      <StatCard label="Succeeded" value={stats.succeeded ?? 0} />
      <StatCard label="Failed" value={stats.failed ?? 0} accent={stats.failed > 0} />
      <StatCard
        label="Avg duration"
        value={stats.avg_duration_ms != null ? `${stats.avg_duration_ms}ms` : '—'}
      />
    </div>
  )
}

function StatCard({ label, value, accent = false }) {
  return (
    <div className={`border border-border rounded-md p-3 ${accent ? 'bg-red-50' : 'bg-card'}`}>
      <div className="text-xs text-muted-foreground mb-1">{label}</div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  )
}

function RunStatusBadge({ status }) {
  const map = {
    success: { Icon: CheckCircle2, cls: 'bg-emerald-100 text-emerald-800 ring-emerald-200', label: 'Success' },
    failed: { Icon: XCircle, cls: 'bg-red-100 text-red-800 ring-red-200', label: 'Failed' },
    running: { Icon: Loader2, cls: 'bg-blue-100 text-blue-800 ring-blue-200', label: 'Running' },
  }
  const cfg = map[status] || map.running
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium ring-1 ring-inset ${cfg.cls}`}>
      <cfg.Icon className={`w-3 h-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
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
          <option key={o.value} value={o.value} className="capitalize">{o.label}</option>
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
