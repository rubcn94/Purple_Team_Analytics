export default function StatCard({ icon: Icon, label, value, sub, accent = 'purple' }) {
  const accents = {
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    red:    'text-red-400 bg-red-500/10 border-red-500/20',
    cyan:   'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    green:  'text-green-400 bg-green-500/10 border-green-500/20',
  }
  return (
    <div className="card flex items-center gap-4">
      <div className={`p-3 rounded-xl border ${accents[accent]}`}>
        <Icon size={22} className={accents[accent].split(' ')[0]} />
      </div>
      <div className="min-w-0">
        <p className="text-gray-400 text-sm">{label}</p>
        <p className="text-2xl font-bold text-white">{value}</p>
        {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}
