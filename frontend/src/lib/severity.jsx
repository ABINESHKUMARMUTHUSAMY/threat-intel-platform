export const severityConfig = {
  low:      { label: 'Low',      bg: 'bg-slate-100',   text: 'text-slate-700',   ring: 'ring-slate-200' },
  medium:   { label: 'Medium',   bg: 'bg-amber-100',   text: 'text-amber-800',   ring: 'ring-amber-200' },
  high:     { label: 'High',     bg: 'bg-orange-100',  text: 'text-orange-800',  ring: 'ring-orange-200' },
  critical: { label: 'Critical', bg: 'bg-red-100',     text: 'text-red-800',     ring: 'ring-red-200' },
}

export function SeverityBadge({ severity }) {
  const cfg = severityConfig[severity] || severityConfig.low
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ring-1 ring-inset ${cfg.bg} ${cfg.text} ${cfg.ring}`}>
      {cfg.label}
    </span>
  )
}
