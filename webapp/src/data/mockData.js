export const audits = [
  {
    id: 'AUD-001',
    client: 'Restaurante La Brasa',
    url: 'https://labrasa.es',
    target: '185.23.44.11',
    date: '2026-05-15',
    type: 'prospect',
    status: 'completed',
    riskScore: 72,
    duration: '3m 12s',
    modules: ['http', 'ssl_tls', 'compliance'],
    findings: [
      { id: 'f1', severity: 'critical', title: 'Sin HTTPS activo', module: 'ssl_tls', description: 'El sitio opera sin cifrado TLS. Cualquier dato transmitido (formularios, contraseñas) es interceptable en claro.' },
      { id: 'f2', severity: 'high', title: 'Headers de seguridad ausentes', module: 'http', description: 'Faltan Content-Security-Policy, HSTS, X-Frame-Options y X-Content-Type-Options.' },
      { id: 'f3', severity: 'medium', title: 'Cookie de sesión sin flags seguros', module: 'http', description: 'La cookie de sesión carece de los atributos Secure y HttpOnly, exponiéndola a XSS y transmisión en claro.' },
      { id: 'f4', severity: 'low', title: 'Versión de servidor expuesta', module: 'http', description: 'La cabecera Server revela Apache 2.4.29 facilitando fingerprinting del servidor.' },
      { id: 'f5', severity: 'info', title: 'Sin política de privacidad visible', module: 'compliance', description: 'No se detectó enlace a política de privacidad en la página principal (requerido por RGPD Art. 13).' },
    ],
  },
  {
    id: 'AUD-002',
    client: 'Clínica Dental Mora',
    url: 'https://clinicamora.es',
    target: '91.108.56.23',
    date: '2026-05-12',
    type: 'external',
    status: 'completed',
    riskScore: 58,
    duration: '41m 05s',
    modules: ['http', 'ssl_tls', 'osint', 'subdomain', 'compliance', 'cve'],
    findings: [
      { id: 'f6', severity: 'critical', title: 'Panel de administración expuesto', module: 'http', description: 'Ruta /admin/ accesible sin autenticación adicional desde Internet. Expone CMS WordPress.' },
      { id: 'f7', severity: 'high', title: 'WordPress 5.8 desactualizado (CVE-2021-44223)', module: 'cve', description: 'Versión de WordPress con vulnerabilidad XSS documentada. Actualización crítica disponible.' },
      { id: 'f8', severity: 'high', title: 'Certificado SSL expira en 12 días', module: 'ssl_tls', description: 'El certificado TLS vence el 27/05/2026. Un certificado expirado interrumpe el servicio.' },
      { id: 'f9', severity: 'medium', title: 'Subdominio staging.clinicamora.es sin seguridad', module: 'subdomain', description: 'Subdominio de desarrollo accesible públicamente con datos de prueba y sin HTTPS.' },
      { id: 'f10', severity: 'medium', title: 'Email corporativo en brechas de datos', module: 'osint', description: 'info@clinicamora.es encontrado en 2 brechas (Mailchimp 2022, LinkedIn 2021).' },
      { id: 'f11', severity: 'low', title: 'DMARC no configurado', module: 'osint', description: 'Sin registro DMARC el dominio es susceptible a spoofing de email corporativo.' },
    ],
  },
  {
    id: 'AUD-003',
    client: 'Autoescuela Rápido',
    url: 'https://autoescuelarapido.com',
    target: '212.45.67.89',
    date: '2026-05-08',
    type: 'prospect',
    status: 'completed',
    riskScore: 41,
    duration: '2m 48s',
    modules: ['http', 'ssl_tls', 'compliance'],
    findings: [
      { id: 'f12', severity: 'high', title: 'Protocolo TLS 1.0 habilitado', module: 'ssl_tls', description: 'El servidor acepta TLS 1.0, protocolo con vulnerabilidades conocidas (POODLE, BEAST).' },
      { id: 'f13', severity: 'medium', title: 'Formulario de contacto sin CAPTCHA', module: 'compliance', description: 'El formulario de recogida de datos no implementa protección contra bots (recomendado RGPD).' },
      { id: 'f14', severity: 'low', title: 'Redirección HTTP→HTTPS inconsistente', module: 'ssl_tls', description: 'Algunas rutas no redirigen automáticamente a HTTPS, creando contenido mixto.' },
      { id: 'f15', severity: 'info', title: 'Google Analytics sin anonimización de IP', module: 'compliance', description: 'Analytics instalado sin activar anonymizeIp, incumpliendo recomendaciones RGPD.' },
    ],
  },
  {
    id: 'AUD-004',
    client: 'Hotel Costa Azul',
    url: 'https://hotelcostaazul.es',
    target: '82.223.15.44',
    date: '2026-05-01',
    type: 'external',
    status: 'completed',
    riskScore: 85,
    duration: '55m 22s',
    modules: ['http', 'ssl_tls', 'osint', 'subdomain', 'network', 'compliance', 'cve', 'web_discovery'],
    findings: [
      { id: 'f16', severity: 'critical', title: 'Inyección SQL en motor de reservas', module: 'web_discovery', description: 'Parámetro ?id= del motor de reservas vulnerable a SQLi clásico. Permite extracción de BBDD.' },
      { id: 'f17', severity: 'critical', title: 'Puerto RDP (3389) expuesto a Internet', module: 'network', description: 'Servidor Windows con RDP accesible desde cualquier IP. Historial de ataques de fuerza bruta.' },
      { id: 'f18', severity: 'high', title: 'Credenciales admin por defecto en router', module: 'network', description: 'Router de recepción accesible con admin/admin. Permite reconfigurar la red del hotel.' },
      { id: 'f19', severity: 'high', title: 'Datos de tarjetas en logs de servidor', module: 'compliance', description: 'Los logs de Apache contienen PAN parciales de tarjetas en parámetros GET. Incumplimiento PCI-DSS.' },
      { id: 'f20', severity: 'medium', title: 'OSINT: plano de red en documento público', module: 'osint', description: 'Documento PDF en Google indexado contiene diagrama de red interna del hotel.' },
      { id: 'f21', severity: 'medium', title: 'XSS en buscador interno', module: 'web_discovery', description: 'El campo de búsqueda de habitaciones refleja input sin sanitizar.' },
    ],
  },
  {
    id: 'AUD-005',
    client: 'Farmacia San Juan',
    url: 'https://farmaciasanjuan.es',
    target: '109.68.201.55',
    date: '2026-04-25',
    type: 'prospect',
    status: 'completed',
    riskScore: 30,
    duration: '2m 55s',
    modules: ['http', 'ssl_tls', 'compliance'],
    findings: [
      { id: 'f22', severity: 'medium', title: 'Cabecera Referrer-Policy ausente', module: 'http', description: 'Sin Referrer-Policy los usuarios pueden filtrar datos de navegación a sitios terceros.' },
      { id: 'f23', severity: 'low', title: 'Cookies de terceros sin consentimiento', module: 'compliance', description: 'Se detectaron 4 cookies de terceros (Google, Facebook) cargadas antes de aceptar el banner.' },
      { id: 'f24', severity: 'info', title: 'Botón "Pedir cita" sin HTTPS en destino', module: 'ssl_tls', description: 'El enlace de cita online apunta a http:// en lugar de https://.' },
    ],
  },
  {
    id: 'AUD-006',
    client: 'Gestoría Martínez & Asociados',
    url: 'https://gestoria-martinez.com',
    target: '195.110.88.21',
    date: '2026-04-18',
    type: 'external',
    status: 'completed',
    riskScore: 66,
    duration: '38m 11s',
    modules: ['http', 'ssl_tls', 'osint', 'subdomain', 'compliance', 'cve'],
    findings: [
      { id: 'f25', severity: 'critical', title: 'Portal cliente sin 2FA', module: 'compliance', description: 'El portal de clientes con acceso a documentos fiscales confidenciales solo usa usuario/contraseña.' },
      { id: 'f26', severity: 'high', title: 'Directory listing activo en /uploads/', module: 'http', description: 'La carpeta /uploads/ lista todos los archivos subidos, incluyendo declaraciones de renta y nóminas.' },
      { id: 'f27', severity: 'high', title: 'Empleado con credenciales en brecha (2023)', module: 'osint', description: '3 empleados encontrados en la brecha de LinkedIn 2023 con contraseñas hasheadas expuestas.' },
      { id: 'f28', severity: 'medium', title: 'Joomla 3.9 sin actualizar', module: 'cve', description: 'Versión del CMS con múltiples CVEs conocidos. Parche disponible desde hace 18 meses.' },
      { id: 'f29', severity: 'low', title: 'Subdominio webmail accesible', module: 'subdomain', description: 'webmail.gestoria-martinez.com expone versión de Roundcube 1.4.1.' },
    ],
  },
]

export const moduleColors = {
  http: '#8b5cf6',
  ssl_tls: '#06b6d4',
  osint: '#10b981',
  subdomain: '#f59e0b',
  network: '#ef4444',
  compliance: '#ec4899',
  cve: '#f97316',
  web_discovery: '#6366f1',
  wifi: '#14b8a6',
  bluetooth: '#a855f7',
  blue_team: '#3b82f6',
}

export const severityConfig = {
  critical: { label: 'Crítico', color: '#ef4444', bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', order: 0 },
  high:     { label: 'Alto',    color: '#f97316', bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30', order: 1 },
  medium:   { label: 'Medio',   color: '#eab308', bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', order: 2 },
  low:      { label: 'Bajo',    color: '#3b82f6', bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30', order: 3 },
  info:     { label: 'Info',    color: '#6b7280', bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', order: 4 },
}

export function getRiskLevel(score) {
  if (score >= 75) return { label: 'Crítico', color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30' }
  if (score >= 55) return { label: 'Alto', color: 'text-orange-400', bg: 'bg-orange-500/20', border: 'border-orange-500/30' }
  if (score >= 35) return { label: 'Medio', color: 'text-yellow-400', bg: 'bg-yellow-500/20', border: 'border-yellow-500/30' }
  return { label: 'Bajo', color: 'text-green-400', bg: 'bg-green-500/20', border: 'border-green-500/30' }
}

export function countBySeverity(findings) {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})
}
