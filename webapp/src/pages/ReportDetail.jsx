import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Calendar, Clock, Globe, Shield, ChevronDown, ChevronUp, Download } from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import SeverityBadge from '../components/SeverityBadge'
import { audits, severityConfig, getRiskLevel, countBySeverity, moduleColors } from '../data/mockData'

const MODULE_LABELS = {
  http: 'HTTP / Headers',
  ssl_tls: 'SSL / TLS',
  osint: 'OSINT',
  subdomain: 'Subdominios',
  network: 'Red Interna',
  compliance: 'Compliance',
  cve: 'CVE Scan',
  web_discovery: 'Web Discovery',
  wifi: 'WiFi',
  bluetooth: 'Bluetooth',
  blue_team: 'Blue Team',
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-surface-600 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-surface-700/40 transition-colors"
      >
        <SeverityBadge severity={f.severity} />
        <span className="flex-1 text-sm font-medium text-gray-200">{f.title}</span>
        <span className="text-xs text-gray-600 font-mono">{MODULE_LABELS[f.module] || f.module}</span>
        {open ? <ChevronUp size={14} className="text-gray-500 shrink-0" /> : <ChevronDown size={14} className="text-gray-500 shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 bg-surface-700/20 border-t border-surface-600">
          <p className="text-gray-400 text-sm leading-relaxed mt-3">{f.description}</p>
          <div className="mt-3 flex items-center gap-2">
            <span className="text-xs text-gray-600">Módulo:</span>
            <span
              className="text-xs font-medium px-2 py-0.5 rounded"
              style={{ backgroundColor: (moduleColors[f.module] || '#7c3aed') + '20', color: moduleColors[f.module] || '#a78bfa' }}
            >
              {MODULE_LABELS[f.module] || f.module}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

export default function ReportDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const audit = audits.find(a => a.id === id)

  if (!audit) {
    return (
      <div className="text-center py-24">
        <p className="text-gray-500">Informe no encontrado.</p>
        <button onClick={() => navigate('/reports')} className="btn-ghost mt-4 text-sm">Volver a Informes</button>
      </div>
    )
  }

  const risk = getRiskLevel(audit.riskScore)
  const counts = countBySeverity(audit.findings)

  const pieData = Object.entries(counts)
    .sort((a, b) => severityConfig[a[0]].order - severityConfig[b[0]].order)
    .map(([sev, count]) => ({ name: severityConfig[sev].label, value: count, color: severityConfig[sev].color }))

  const grouped = audit.findings.reduce((acc, f) => {
    acc[f.severity] = acc[f.severity] || []
    acc[f.severity].push(f)
    return acc
  }, {})

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

  const handleExport = () => {
    const lines = [
      `INFORME DE AUDITORÍA — ${audit.client}`,
      `URL: ${audit.url}`,
      `Fecha: ${audit.date}`,
      `Riesgo: ${audit.riskScore}/100 (${risk.label})`,
      '',
      'HALLAZGOS:',
      ...audit.findings.map(f => `[${f.severity.toUpperCase()}] ${f.title}\n  ${f.description}`),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `Informe_${audit.client.replace(/\s+/g, '_')}_${audit.date}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="max-w-3xl space-y-5">
      {/* Back */}
      <button onClick={() => navigate('/reports')} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-300 transition-colors">
        <ArrowLeft size={15} /> Volver a Informes
      </button>

      {/* Header */}
      <div className="card">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-xl font-bold text-white">{audit.client}</h1>
            <p className="text-gray-500 text-sm font-mono mt-1">{audit.url}</p>
            <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
              <span className="flex items-center gap-1"><Calendar size={11} />{audit.date}</span>
              <span className="flex items-center gap-1"><Clock size={11} />{audit.duration}</span>
              <span className="flex items-center gap-1"><Globe size={11} />{audit.target}</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-3">
            <div className="text-right">
              <p className="text-xs text-gray-500 mb-1">Puntuación de Riesgo</p>
              <p className={`text-4xl font-bold ${risk.color}`}>{audit.riskScore}</p>
              <span className={`text-xs px-2 py-0.5 rounded-full ${risk.bg} ${risk.color} border ${risk.border}`}>{risk.label}</span>
            </div>
            <button onClick={handleExport} className="btn-ghost flex items-center gap-2 text-xs border border-surface-600">
              <Download size={13} /> Exportar TXT
            </button>
          </div>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Pie */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Distribución de Hallazgos</h2>
          <div className="flex items-center gap-4">
            <ResponsiveContainer width="55%" height={140}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={38} outerRadius={62} dataKey="value" stroke="none">
                  {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1a1a26', border: '1px solid #222233', borderRadius: '8px', fontSize: 12 }}
                  itemStyle={{ color: '#d1d5db' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-1.5 flex-1">
              {pieData.map(d => (
                <div key={d.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-gray-400">{d.name}</span>
                  </div>
                  <span className="text-white font-semibold">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Modules */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-3">Módulos Ejecutados</h2>
          <div className="flex flex-wrap gap-2">
            {audit.modules.map(m => (
              <span
                key={m}
                className="text-xs font-medium px-2.5 py-1 rounded-lg"
                style={{ backgroundColor: (moduleColors[m] || '#7c3aed') + '20', color: moduleColors[m] || '#a78bfa' }}
              >
                {MODULE_LABELS[m] || m}
              </span>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-surface-600 grid grid-cols-2 gap-2 text-xs">
            <div>
              <p className="text-gray-500">Total hallazgos</p>
              <p className="text-white font-bold text-lg">{audit.findings.length}</p>
            </div>
            <div>
              <p className="text-gray-500">Tipo de análisis</p>
              <p className="text-white font-medium capitalize">{audit.type}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Shield size={14} className="text-purple-400" /> Hallazgos Detallados
        </h2>
        <div className="space-y-2">
          {severityOrder
            .filter(s => grouped[s])
            .flatMap(s => grouped[s])
            .map(f => <FindingRow key={f.id} f={f} />)
          }
        </div>
      </div>
    </div>
  )
}
