import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanSearch,
  FileText,
  Shield,
  ChevronRight,
} from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/scan/new', icon: ScanSearch, label: 'Nuevo Análisis' },
  { to: '/reports', icon: FileText, label: 'Informes' },
]

export default function Sidebar() {
  return (
    <aside className="w-60 shrink-0 bg-surface-800 border-r border-surface-600 flex flex-col h-screen sticky top-0">
      {/* Logo */}
      <div className="px-5 py-6 border-b border-surface-600">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-purple-600 flex items-center justify-center">
            <Shield size={18} className="text-white" />
          </div>
          <div>
            <p className="font-bold text-white text-sm leading-tight">Purple Team</p>
            <p className="text-purple-400 text-xs">Analytics</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group ${
                isActive
                  ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-surface-700'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <Icon size={17} />
                <span className="flex-1">{label}</span>
                {isActive && <ChevronRight size={14} className="text-purple-400" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-surface-600">
        <p className="text-gray-600 text-xs font-mono">v0.1.0-demo</p>
        <p className="text-gray-700 text-xs mt-0.5">Datos de demostración</p>
      </div>
    </aside>
  )
}
