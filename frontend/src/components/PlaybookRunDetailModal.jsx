import { useQuery } from '@tanstack/react-query'
import { X, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'

export default function PlaybookRunDetailModal({ runId, onClose }) {
  const { data, isLoading } = useQuery({
    queryKey: ['playbook-run', runId],
    queryFn: () => api.get(`/playbook-runs/${runId}`).then(r => r.data),
    enabled: !!runId,
  })

  if (!runId) return null

  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-card border border-border rounded-lg shadow-xl w-full max-w-3xl max-h-[85vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-border sticky top-0 bg-card">
          <h3 className="text-base font-semibold">Playbook run details</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 rounded">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5">
          {isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}
          {data && <RunDetails run={data} />}
        </div>
      </div>
    </div>
  )
}

function RunDetails({ run }) {
  const actions = Array.isArray(run.actions_taken) ? run.actions_taken : []

  return (
    <div className="space-y-5 text-sm">
      <Section label="Execution">
        <KV label="Playbook">{run.playbook_name}</KV>
        <KV label="Status">
          <StatusInline status={run.status} />
        </KV>
        <KV label="Started">{new Date(run.started_at).toLocaleString()}</KV>
        {run.completed_at && <KV label="Completed">{new Date(run.completed_at).toLocaleString()}</KV>}
        <KV label="Duration">{run.duration_ms != null ? `${run.duration_ms}ms` : '—'}</KV>
        {run.error_message && (
          <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-xs text-red-800 font-mono whitespace-pre-wrap">
            {run.error_message}
          </div>
        )}
      </Section>

      <Section label="Triggering alert">
        <KV label="Alert ID"><code className="text-xs">{run.alert_id?.slice(0, 8)}</code></KV>
        <KV label="Attack type">{run.attack_type || '—'}</KV>
        <KV label="Severity">{run.severity || '—'}</KV>
        <KV label="Confidence">
          {run.confidence != null ? `${(run.confidence * 100).toFixed(1)}%` : '—'}
        </KV>
        <KV label="Source IP"><code className="text-xs">{run.src_ip || '—'}</code></KV>
        <KV label="Destination IP"><code className="text-xs">{run.dst_ip || '—'}</code></KV>
        {run.alert_description && (
          <div className="text-xs text-muted-foreground font-mono mt-2 whitespace-pre-wrap">
            {run.alert_description}
          </div>
        )}
      </Section>

      <Section label={`Actions taken (${actions.length})`}>
        {actions.length === 0 ? (
          <div className="text-muted-foreground text-xs">No actions recorded</div>
        ) : (
          <div className="space-y-2">
            {actions.map((action, i) => (
              <ActionCard key={i} action={action} index={i + 1} />
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

function ActionCard({ action, index }) {
  const { type, ...rest } = action
  return (
    <div className="border border-border rounded p-3 bg-secondary/30">
      <div className="flex items-baseline justify-between mb-2">
        <span className="text-xs font-medium uppercase tracking-wide">
          {index}. {type || 'action'}
        </span>
        {rest.dry_run && (
          <span className="text-xs bg-amber-100 text-amber-800 px-1.5 py-0.5 rounded">DRY RUN</span>
        )}
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        {Object.entries(rest).map(([k, v]) => {
          if (k === 'dry_run') return null
          let display = v
          if (Array.isArray(v)) display = v.join(', ')
          else if (v === null) display = 'null'
          else if (typeof v === 'object') display = JSON.stringify(v)
          return (
            <div key={k} className="contents">
              <div className="text-muted-foreground">{k}</div>
              <div className="font-mono text-right break-all">{String(display)}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function StatusInline({ status }) {
  if (status === 'success') return <span className="text-emerald-700">Success</span>
  if (status === 'failed') return <span className="text-red-700">Failed</span>
  return <span className="text-blue-700">Running</span>
}

function Section({ label, children }) {
  return (
    <div>
      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-2">{label}</div>
      <div className="space-y-1">{children}</div>
    </div>
  )
}

function KV({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-0.5">
      <div className="text-muted-foreground text-xs">{label}</div>
      <div className="text-right">{children}</div>
    </div>
  )
}
