import { useQuery } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { api } from '@/lib/api'
import { SeverityBadge } from '@/lib/severity'

export default function AlertDetailModal({ alertId, onClose }) {
  const { data, isLoading } = useQuery({
    queryKey: ['alert', alertId],
    queryFn: () => api.get(`/alerts/${alertId}`).then(r => r.data),
    enabled: !!alertId,
  })

  if (!alertId) return null

  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-card border border-border rounded-lg shadow-xl w-full max-w-3xl max-h-[85vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-border sticky top-0 bg-card">
          <h3 className="text-base font-semibold">Alert details</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5">
          {isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}
          {data && <AlertDetails alert={data} />}
        </div>
      </div>
    </div>
  )
}

function AlertDetails({ alert }) {
  const raw = alert.raw_features || {}
  const probs = raw.xgb_all_proba || {}
  const sortedProbs = Object.entries(probs).sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-5 text-sm">
      <Section label="Summary">
        <KV label="Attack type">{alert.attack_type}</KV>
        <KV label="Severity"><SeverityBadge severity={alert.severity} /></KV>
        <KV label="Confidence">{(alert.confidence * 100).toFixed(1)}%</KV>
        <KV label="Timestamp">{new Date(alert.timestamp).toLocaleString()}</KV>
        <KV label="Status">{alert.status}</KV>
      </Section>

      <Section label="Network">
        <KV label="Source IP"><code className="text-xs">{alert.src_ip}</code></KV>
        <KV label="Destination IP"><code className="text-xs">{alert.dst_ip}</code></KV>
        {raw.src_port != null && <KV label="Source port">{raw.src_port}</KV>}
        {raw.dst_port != null && <KV label="Destination port">{raw.dst_port}</KV>}
        {raw.protocol && <KV label="Protocol">{raw.protocol}</KV>}
      </Section>

      <Section label="XGBoost classification">
        {sortedProbs.length > 0 ? (
          <div className="space-y-1.5">
            {sortedProbs.map(([cls, p]) => (
              <div key={cls} className="flex items-center gap-3">
                <div className="w-28 text-xs">{cls}</div>
                <div className="flex-1 bg-muted rounded h-2 overflow-hidden">
                  <div
                    className="h-full bg-primary"
                    style={{ width: `${(p * 100).toFixed(1)}%` }}
                  />
                </div>
                <div className="text-xs w-14 text-right font-mono">{(p * 100).toFixed(1)}%</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-muted-foreground">No XGBoost probabilities recorded</div>
        )}
      </Section>

      <Section label="Anomaly detection">
        <KV label="IF flagged anomalous">{String(raw.iso_anomaly ?? 'n/a')}</KV>
        {raw.iso_score != null && <KV label="IF score">{Number(raw.iso_score).toFixed(3)}</KV>}
      </Section>

      <Section label="Flow features">
        {raw.flow_features ? (
          <div className="grid grid-cols-2 gap-x-6 gap-y-1">
            {Object.entries(raw.flow_features).map(([k, v]) => (
              <KV key={k} label={k}>{typeof v === 'number' ? v.toFixed(2) : String(v)}</KV>
            ))}
          </div>
        ) : (
          <div className="text-muted-foreground">No flow features recorded</div>
        )}
      </Section>

      <Section label="Description">
        <div className="text-xs text-muted-foreground font-mono whitespace-pre-wrap">
          {alert.description}
        </div>
      </Section>
    </div>
  )
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
