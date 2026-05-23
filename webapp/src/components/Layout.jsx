import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'

const titles = {
  '/': 'Dashboard',
  '/scan/new': 'Nuevo Análisis',
  '/reports': 'Informes',
}

export default function Layout() {
  const { pathname } = useLocation()
  const title = Object.keys(titles)
    .sort((a, b) => b.length - a.length)
    .find(k => pathname === k || pathname.startsWith(k + '/'))

  return (
    <div className="flex min-h-screen bg-surface-900">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        {/* Topbar */}
        <header className="bg-surface-800/60 backdrop-blur border-b border-surface-600 px-8 py-4 flex items-center justify-between sticky top-0 z-10">
          <h1 className="text-lg font-semibold text-white">{titles[title] || 'Informe'}</h1>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse-slow" />
            <span className="text-xs text-gray-500">Modo demo</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 px-8 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
