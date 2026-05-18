import { useNavigate } from 'react-router-dom'
import { Shield, AlertTriangle, Users, TrendingUp, Plus, ArrowRight } from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import { audits, severityConfig, getRiskLevel, countBySeverity } from '../data/mockData'

const allFindings = audits.flatMap(a => a.findings)
const severityCounts = countBySeverity(allFindings)

const pieData = Object.entries(severityCounts)
  .sort((a, b) => severityConfig[a[0]].order - severityConfig[b[0]].order)
  .map(([sev, count]) => ({
    name: severityConfig[sev].label,
    value: count,
    color: severityConfig[sev].color,
  }))

const barData = audits
  .slice()
  .sort((a, b) => new Date(a.date) - new Date(b.date))
  .map(a => ({
    name: a.client.split(' ').slice(0, 2).join(' '),
    score: a.riskScore,
    fill: a.riskScore >= 75 ? '#ef4444' : a.riskScore >= 55 ? '#f97316' : a.riskScore >= 35 ? '#eab308' : '#22c55e',
  }))

const CustomTooltipPie = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-700 border border-surface-600 rounded-lg px-3 py-2 text-sm">
      <span className="text-gray-300">{payload[0].name}: </span>
      <span className="text-white font-bold">{payload[0].value}</span>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const totalFindings = allFindings.length
  const criticalCount = severityCounts.critical || 0
  const avgRisk = Math.round(audits.reduce((s, a) => s + a.riskScore, 0) / audits.length)
  const clientCount = new Set(audits.map(a => a.client)).size

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield} label="Total Auditorías" value={audits.length} sub="Últimos 90 días" accent="purple" />
        <StatCard icon={AlertTriangle} label="Hallazgos Críticos" value={criticalCount} sub={`de ${totalFindings} totales`} accent="red" />
        <StatCard icon={Users} label="Clientes Analizados" value={clientCount} sub="Activos" accent="cyan" />
        <StatCard icon={TrendingUp} label="Riesgo Promedio" value={`${avgRisk}/100`} sub="Escala de severidad" accent="green" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Pie chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Distribución de Hallazgos</h2>
          <div className="flex items-center gap-6">
            <ResponsiveContainer width="50%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" stroke="none">
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip content={<CustomTooltipPie />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2 flex-1">
              {pieData.map(d => (
                <div key={d.name} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-gray-400">{d.name}</span>
                  </div>
                  <span className="text-white font-medium">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Bar chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Puntuación de Riesgo por Cliente</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={barData} barSize={28}>
              <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                cursor={{ fill: 'rgba(139, 92, 246, 0.08)' }}
                contentStyle={{ background: '#1a1a26', border: '1px solid #222233', borderRadius: '8px', fontSize: 12 }}
                labelStyle={{ color: '#e5e7eb' }}
                itemStyle={{ color: '#d1d5db' }}
              />
              <Bar dataKey="score" radius={[4, 4, 0, 0]} label={false}>
                {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent audits */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-gray-300">Últimas Auditorías</h2>
          <button onClick={() => navigate('/scan/new')} className="btn-primary flex items-center gap-2 text-sm">
            <Plus size={15} /> Nueva
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600 text-gray-500 text-xs uppercase tracking-wide">
                <th className="text-left pb-3 pr-4">Cliente</th>
                <th className="text-left pb-3 pr-4">URL</th>
                <th className="text-left pb-3 pr-4">Fecha</th>
                <th className="text-left pb-3 pr-4">Hallazgos</th>
                <th className="text-left pb-3 pr-4">Riesgo</th>
                <th className="pb-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-600">
              {audits.slice(0, 5).map(a => {
                const risk = getRiskLevel(a.riskScore)
                const counts = countBySeverity(a.findings)
                return (
                  <tr key={a.id} className="hover:bg-surface-700/40 transition-colors group">
                    <td className="py-3 pr-4 font-medium text-gray-200">{a.client}</td>
                    <td className="py-3 pr-4 text-gray-500 font-mono text-xs">{a.url}</td>
                    <td className="py-3 pr-4 text-gray-400">{a.date}</td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-1.5">
                        {counts.critical > 0 && <span className="badge-critical">{counts.critical}C</span>}
                        {counts.high > 0 && <span className="badge-high">{counts.high}A</span>}
                        {counts.medium > 0 && <span className="badge-medium">{counts.medium}M</span>}
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`${risk.bg} ${risk.color} border ${risk.border} text-xs font-medium px-2 py-0.5 rounded-full`}>
                        {a.riskScore} — {risk.label}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => navigate(`/reports/${a.id}`)}
                        className="text-gray-600 group-hover:text-purple-400 transition-colors"
                      >
                        <ArrowRight size={16} />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
