import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ArrowRight, FileText, Calendar, AlertTriangle } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'
import { audits, getRiskLevel, countBySeverity } from '../data/mockData'

const TYPE_LABELS = { prospect: 'Prospección', external: 'Ext. Completa', full: 'Suite Completa' }

export default function Reports() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [filterRisk, setFilterRisk] = useState('all')

  const filtered = audits.filter(a => {
    const matchSearch = !search || a.client.toLowerCase().includes(search.toLowerCase()) || a.url.includes(search)
    const matchRisk = filterRisk === 'all' || (
      filterRisk === 'critical' ? a.riskScore >= 75 :
      filterRisk === 'high'     ? a.riskScore >= 55 && a.riskScore < 75 :
      filterRisk === 'medium'   ? a.riskScore >= 35 && a.riskScore < 55 :
                                   a.riskScore < 35
    )
    return matchSearch && matchRisk
  })

  return (
    <div className="space-y-5">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="input pl-9"
            placeholder="Buscar cliente o URL..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="input w-auto min-w-[160px]"
          value={filterRisk}
          onChange={e => setFilterRisk(e.target.value)}
        >
          <option value="all">Todos los riesgos</option>
          <option value="critical">Crítico (≥75)</option>
          <option value="high">Alto (55-74)</option>
          <option value="medium">Medio (35-54)</option>
          <option value="low">Bajo (&lt;35)</option>
        </select>
      </div>

      {/* Count */}
      <p className="text-xs text-gray-500">{filtered.length} informe{filtered.length !== 1 ? 's' : ''}</p>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {filtered.map(a => {
          const risk = getRiskLevel(a.riskScore)
          const counts = countBySeverity(a.findings)
          return (
            <div
              key={a.id}
              onClick={() => navigate(`/reports/${a.id}`)}
              className="card cursor-pointer hover:border-purple-500/40 transition-all duration-150 group"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="font-semibold text-white group-hover:text-purple-300 transition-colors">{a.client}</h3>
                  <p className="text-gray-500 text-xs font-mono mt-0.5">{a.url}</p>
                </div>
                <span className={`${risk.bg} ${risk.color} border ${risk.border} text-xs font-bold px-2 py-0.5 rounded-full`}>
                  {a.riskScore}
                </span>
              </div>

              <div className="flex items-center gap-4 text-xs text-gray-500 mb-4">
                <span className="flex items-center gap-1"><Calendar size={11} />{a.date}</span>
                <span className="flex items-center gap-1"><FileText size={11} />{TYPE_LABELS[a.type]}</span>
                <span className="flex items-center gap-1"><AlertTriangle size={11} />{a.findings.length} hallazgos</span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  {counts.critical > 0 && <span className="badge-critical">{counts.critical} crítico{counts.critical > 1 ? 's' : ''}</span>}
                  {counts.high > 0 && <span className="badge-high">{counts.high} alto{counts.high > 1 ? 's' : ''}</span>}
                  {counts.medium > 0 && <span className="badge-medium">{counts.medium} medio{counts.medium > 1 ? 's' : ''}</span>}
                  {counts.low > 0 && <span className="badge-low">{counts.low} bajo{counts.low > 1 ? 's' : ''}</span>}
                </div>
                <ArrowRight size={15} className="text-gray-600 group-hover:text-purple-400 transition-colors" />
              </div>
            </div>
          )
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-16 text-gray-600">
          <FileText size={32} className="mx-auto mb-3 opacity-30" />
          <p>No se encontraron informes</p>
        </div>
      )}
    </div>
  )
}
