import { severityConfig } from '../data/mockData'

export default function SeverityBadge({ severity, size = 'sm' }) {
  const cfg = severityConfig[severity] || severityConfig.info
  const padding = size === 'lg' ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-xs'
  return (
    <span className={`${cfg.bg} ${cfg.text} border ${cfg.border} font-medium rounded-full ${padding}`}>
      {cfg.label}
    </span>
  )
}
