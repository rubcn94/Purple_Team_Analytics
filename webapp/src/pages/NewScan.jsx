import { useState } from 'react'
import {
  Globe, Server, User, Zap, Shield, Layers, ChevronRight,
  Wifi, Search, FileCheck, Network, Eye, Bug,
} from 'lucide-react'

const scanProfiles = [
  {
    id: 'prospect',
    icon: Zap,
    title: 'Prospección Rápida',
    duration: '2-3 min',
    desc: 'Diagnóstico express para mostrar a un cliente potencial. HTTP, SSL y RGPD básico.',
    modules: ['http', 'ssl_tls', 'compliance'],
    accent: 'border-cyan-500/40 hover:border-cyan-400/60',
    tag: 'bg-cyan-500/20 text-cyan-400',
  },
  {
    id: 'external',
    icon: Shield,
    title: 'Auditoría Externa',
    duration: '30-60 min',
    desc: 'Análisis completo de superficie externa: web, DNS, subdominios, CVEs y OSINT.',
    modules: ['http', 'ssl_tls', 'osint', 'subdomain', 'compliance', 'cve'],
    accent: 'border-purple-500/40 hover:border-purple-400/60',
    tag: 'bg-purple-500/20 text-purple-400',
  },
  {
    id: 'full',
    icon: Layers,
    title: 'Suite Completa',
    duration: '1-2 h',
    desc: 'Auditoría integral: todo lo anterior + WiFi, Bluetooth, red interna y Blue Team.',
    modules: ['http', 'ssl_tls', 'osint', 'subdomain', 'compliance', 'cve', 'network', 'wifi', 'bluetooth', 'blue_team'],
    accent: 'border-orange-500/40 hover:border-orange-400/60',
    tag: 'bg-orange-500/20 text-orange-400',
  },
]

const allModules = [
  { id: 'http', icon: Globe, label: 'HTTP/Headers' },
  { id: 'ssl_tls', icon: Shield, label: 'SSL/TLS' },
  { id: 'osint', icon: Search, label: 'OSINT' },
  { id: 'subdomain', icon: Network, label: 'Subdominios' },
  { id: 'compliance', icon: FileCheck, label: 'Compliance' },
  { id: 'cve', icon: Bug, label: 'CVE Scan' },
  { id: 'network', icon: Server, label: 'Red Interna' },
  { id: 'wifi', icon: Wifi, label: 'WiFi' },
  { id: 'web_discovery', icon: Eye, label: 'Web Discovery' },
]

export default function NewScan() {
  const [form, setForm] = useState({ url: '', client: '', target: '' })
  const [profile, setProfile] = useState('prospect')
  const [customModules, setCustomModules] = useState([])
  const [isCustom, setIsCustom] = useState(false)
  const [launched, setLaunched] = useState(false)

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const toggleModule = id => setCustomModules(m => m.includes(id) ? m.filter(x => x !== id) : [...m, id])

  const canSubmit = form.url.trim() && form.client.trim()

  const handleSubmit = e => {
    e.preventDefault()
    if (!canSubmit) return
    setLaunched(true)
  }

  if (launched) {
    return (
      <div className="max-w-lg mx-auto mt-12 text-center card py-12">
        <div className="w-16 h-16 rounded-2xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center mx-auto mb-4">
          <Shield size={28} className="text-purple-400" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Análisis Configurado</h2>
        <p className="text-gray-400 text-sm mb-1">
          <span className="text-gray-200 font-medium">{form.client}</span> · {form.url}
        </p>
        <p className="text-gray-500 text-sm mb-6">
          En la versión completa, el orquestador Python lanzaría los módulos seleccionados
          y generaría el informe PDF automáticamente.
        </p>
        <div className="bg-surface-700 rounded-lg px-4 py-3 text-left font-mono text-xs text-green-400 mb-6">
          <p className="text-gray-500 mb-1"># Comando equivalente:</p>
          <p>python orchestrator.py \</p>
          <p className="pl-4">--mode {isCustom ? 'custom' : profile} \</p>
          <p className="pl-4">--url {form.url} \</p>
          {form.target && <p className="pl-4">--target {form.target} \</p>}
          <p className="pl-4">--client "{form.client}"</p>
        </div>
        <button onClick={() => { setLaunched(false); setForm({ url: '', client: '', target: '' }) }} className="btn-primary">
          Nuevo Análisis
        </button>
      </div>
    )
  }

  return (
    <div className="max-w-2xl space-y-6">
      {/* Target */}
      <div className="card space-y-4">
        <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Globe size={15} className="text-purple-400" /> Objetivo
        </h2>
        <div className="grid grid-cols-1 gap-3">
          <div>
            <label className="text-xs text-gray-500 mb-1.5 block">URL del sitio web *</label>
            <input
              type="url"
              className="input"
              placeholder="https://empresa.com"
              value={form.url}
              onChange={e => set('url', e.target.value)}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-500 mb-1.5 block flex items-center gap-1">
                <User size={11} /> Nombre del cliente *
              </label>
              <input
                className="input"
                placeholder="Empresa SA"
                value={form.client}
                onChange={e => set('client', e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 mb-1.5 block flex items-center gap-1">
                <Server size={11} /> IP / Rango (opcional)
              </label>
              <input
                className="input"
                placeholder="192.168.1.0/24"
                value={form.target}
                onChange={e => set('target', e.target.value)}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Profile */}
      <div className="card space-y-3">
        <h2 className="text-sm font-semibold text-gray-300">Perfil de Análisis</h2>
        <div className="space-y-2">
          {scanProfiles.map(p => (
            <button
              key={p.id}
              onClick={() => { setProfile(p.id); setIsCustom(false) }}
              className={`w-full text-left flex items-start gap-3 px-4 py-3 rounded-xl border transition-all duration-150 ${
                !isCustom && profile === p.id
                  ? p.accent + ' bg-surface-700'
                  : 'border-surface-600 hover:border-surface-500 bg-surface-700/40'
              }`}
            >
              <div className={`mt-0.5 p-2 rounded-lg ${p.tag.split(' ')[0]} border ${p.accent.split(' ')[0]}`}>
                <p.icon size={15} className={p.tag.split(' ')[1]} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-white text-sm">{p.title}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded ${p.tag}`}>{p.duration}</span>
                </div>
                <p className="text-gray-500 text-xs mt-0.5 leading-relaxed">{p.desc}</p>
              </div>
              {!isCustom && profile === p.id && <ChevronRight size={15} className="text-gray-400 mt-1 shrink-0" />}
            </button>
          ))}

          {/* Custom */}
          <button
            onClick={() => setIsCustom(true)}
            className={`w-full text-left flex items-start gap-3 px-4 py-3 rounded-xl border transition-all duration-150 ${
              isCustom
                ? 'border-gray-400/40 bg-surface-700'
                : 'border-surface-600 hover:border-surface-500 bg-surface-700/40'
            }`}
          >
            <div className="mt-0.5 p-2 rounded-lg bg-gray-500/20 border border-gray-500/30">
              <Layers size={15} className="text-gray-400" />
            </div>
            <div>
              <span className="font-medium text-white text-sm">Personalizado</span>
              <p className="text-gray-500 text-xs mt-0.5">Selecciona manualmente qué módulos ejecutar.</p>
            </div>
          </button>
        </div>
      </div>

      {/* Custom modules */}
      {isCustom && (
        <div className="card space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">Seleccionar Módulos</h2>
          <div className="grid grid-cols-3 gap-2">
            {allModules.map(m => {
              const active = customModules.includes(m.id)
              return (
                <button
                  key={m.id}
                  onClick={() => toggleModule(m.id)}
                  className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border text-sm transition-all duration-150 ${
                    active
                      ? 'border-purple-500/50 bg-purple-500/15 text-purple-300'
                      : 'border-surface-600 bg-surface-700/40 text-gray-400 hover:border-surface-500'
                  }`}
                >
                  <m.icon size={14} />
                  <span className="text-xs">{m.label}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Submit */}
      <form onSubmit={handleSubmit}>
        <button
          type="submit"
          disabled={!canSubmit}
          className={`btn-primary w-full py-3 flex items-center justify-center gap-2 ${!canSubmit ? 'opacity-40 cursor-not-allowed' : ''}`}
        >
          <Zap size={16} /> Iniciar Análisis
        </button>
        {!canSubmit && <p className="text-xs text-gray-600 text-center mt-2">Completa URL y nombre del cliente para continuar.</p>}
      </form>
    </div>
  )
}
