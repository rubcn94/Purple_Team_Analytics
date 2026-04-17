# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║        PURPLE TEAM SUITE - PROSPECTING SCANNER               ║
║        Diagnóstico rápido para prospectos (2-3 min)          ║
║                                                              ║
║  Genera informe de diagnóstico enfocado en riesgo legal      ║
║  para presentar a restaurantes, comercios y pymes.           ║
║                                                              ║
║  Uso:                                                        ║
║    python prospect_scan.py --url https://restaurante.com     ║
║    python prospect_scan.py --url https://web.com --client "Bar Sol" ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import ssl
import socket
import json
import argparse
import subprocess
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Colores terminal ──────────────────────────────────────────────────────────
class C:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN  = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    BOLD   = '\033[1m';  DIM = '\033[2m'; END = '\033[0m'

def ok(m):   print(f"{C.GREEN}  ✅  {m}{C.END}")
def warn(m): print(f"{C.YELLOW}  ⚠️   {m}{C.END}")
def bad(m):  print(f"{C.RED}  🔴  {m}{C.END}")
def info(m): print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def hdr(m):  print(f"\n{C.PURPLE}{C.BOLD}  ► {m}{C.END}\n")

BANNER = f"""
{C.PURPLE}{C.BOLD}
  ╔══════════════════════════════════════════════════╗
  ║   🟣  PURPLE TEAM — PROSPECTING SCANNER          ║
  ║        Diagnóstico de seguridad en 3 minutos      ║
  ╚══════════════════════════════════════════════════╝
{C.END}"""

# ── Datos de referencia legal ─────────────────────────────────────────────────
RGPD_FINES = {
    "leve":   ("hasta 10.000.000 €", "o el 2% de la facturación anual global"),
    "grave":  ("hasta 20.000.000 €", "o el 4% de la facturación anual global"),
}

LEGAL_REFS = {
    "ssl_missing":    ("RGPD Art. 32", "grave",  "Ausencia de medidas técnicas de seguridad en transmisión de datos"),
    "ssl_weak":       ("RGPD Art. 32", "leve",   "Cifrado débil en transmisión de datos personales"),
    "ssl_expired":    ("RGPD Art. 32", "grave",  "Certificado SSL expirado — datos en tránsito sin protección válida"),
    "no_cookies":     ("RGPD Art. 13 + ePrivacy", "leve", "Ausencia de banner de consentimiento de cookies"),
    "no_privacy":     ("RGPD Art. 13", "grave",  "Política de privacidad ausente o incompleta"),
    "form_insecure":  ("RGPD Art. 32 + PCI DSS", "grave", "Formularios de datos personales sin cifrado adecuado"),
    "info_disclosure":("RGPD Art. 32", "leve",   "Exposición de tecnología interna facilita ataques dirigidos"),
    "admin_exposed":  ("RGPD Art. 32", "grave",  "Panel de administración accesible — riesgo de acceso no autorizado"),
    "http_headers":   ("RGPD Art. 32", "leve",   "Ausencia de cabeceras de seguridad — vulnerable a ataques web"),
    "no_https":       ("RGPD Art. 32 + PCI DSS", "grave", "Comunicación HTTP sin cifrar — datos personales expuestos en tránsito"),
    "qr_mitm":        ("RGPD Art. 32", "grave",  "QR apunta a URL insegura — susceptible a ataque MitM en red local"),
}


# ── Checks individuales ────────────────────────────────────────────────────────

def check_https(url: str) -> list:
    """Verifica si usa HTTPS y si el certificado es válido."""
    issues = []
    parsed = urlparse(url)
    host = parsed.hostname or url

    if not url.startswith("https://"):
        issues.append({
            "check": "no_https",
            "detail": f"La web usa HTTP sin cifrar",
            "evidence": f"URL: {url}",
        })
        return issues

    # Verificar certificado SSL
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()

        # Fecha expiración
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.utcnow()).days
        if days_left < 0:
            issues.append({"check": "ssl_expired", "detail": f"Certificado SSL expirado hace {abs(days_left)} días", "evidence": f"Expiró: {not_after.strftime('%d/%m/%Y')}"})
        elif days_left < 30:
            issues.append({"check": "ssl_weak", "detail": f"Certificado SSL expira en {days_left} días", "evidence": f"Expira: {not_after.strftime('%d/%m/%Y')}"})

    except ssl.SSLCertVerificationError as e:
        issues.append({"check": "ssl_expired", "detail": "Certificado SSL inválido o no verificable", "evidence": str(e)[:80]})
    except Exception:
        pass  # Conectividad

    # QR check: si es HTTP → MitM trivial
    if not url.startswith("https://"):
        issues.append({"check": "qr_mitm", "detail": "El QR apunta a HTTP — cualquier persona en la misma WiFi puede interceptar y manipular la página", "evidence": f"URL destino: {url}"})

    return issues


def check_http_headers(url: str) -> list:
    """Verifica cabeceras de seguridad HTTP y exposición de tecnología."""
    issues = []
    if not HAS_REQUESTS:
        return issues

    try:
        resp = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScan/1.0)"})
        headers = resp.headers
        final_url = resp.url

        # ¿Acabó en HTTP aunque pedíamos HTTPS?
        if final_url.startswith("http://") and url.startswith("https://"):
            issues.append({"check": "no_https", "detail": "La web redirige de HTTPS a HTTP", "evidence": f"URL final: {final_url}"})

        # Cabeceras de seguridad críticas
        missing = []
        if "Strict-Transport-Security" not in headers:
            missing.append("HSTS")
        if "Content-Security-Policy" not in headers:
            missing.append("CSP")
        if "X-Frame-Options" not in headers:
            missing.append("X-Frame-Options")
        if missing:
            issues.append({"check": "http_headers", "detail": f"Cabeceras de seguridad ausentes: {', '.join(missing)}", "evidence": "Permite ataques XSS, clickjacking e inyección de contenido"})

        # Divulgación de tecnología
        disclosed = []
        if "Server" in headers and any(v in headers["Server"] for v in ["Apache", "nginx", "IIS", "Microsoft"]):
            disclosed.append(f"Servidor: {headers['Server']}")
        if "X-Powered-By" in headers:
            disclosed.append(f"Plataforma: {headers['X-Powered-By']}")
        if disclosed:
            issues.append({"check": "info_disclosure", "detail": "Tecnología interna expuesta públicamente", "evidence": " | ".join(disclosed)})

        # Formularios en la página
        content = resp.text.lower()
        has_form = "<form" in content
        has_input = "type=\"email\"" in content or "type=\"text\"" in content or "reserv" in content or "booking" in content
        if has_form and has_input and not final_url.startswith("https://"):
            issues.append({"check": "form_insecure", "detail": "Formulario de datos personales detectado sin cifrado HTTPS", "evidence": "El formulario transmite datos de clientes en texto plano"})

        # Cookies
        if "Set-Cookie" in headers:
            cookie_str = headers.get("Set-Cookie", "")
            if "Secure" not in cookie_str:
                issues.append({"check": "no_cookies", "detail": "Cookies de sesión sin flag Secure — pueden ser robadas", "evidence": f"Cookie: {cookie_str[:60]}..."})

        # Detectar RGPD/cookies banner ausente
        gdpr_keywords = ["cookie", "privacy", "gdpr", "rgpd", "consentimiento", "acepto", "consent"]
        has_cookie_banner = any(kw in content for kw in gdpr_keywords)
        if not has_cookie_banner:
            issues.append({"check": "no_cookies", "detail": "No se detecta banner de consentimiento de cookies", "evidence": "Obligatorio por Ley 34/2002 (LSSI) y RGPD"})

        # Detectar política de privacidad
        privacy_keywords = ["política de privacidad", "privacy policy", "aviso legal", "protección de datos", "privacidad"]
        has_privacy = any(kw in content for kw in privacy_keywords)
        if not has_privacy:
            issues.append({"check": "no_privacy", "detail": "No se detecta Política de Privacidad en la web", "evidence": "Obligatoria si se recogen datos personales (RGPD Art. 13)"})

    except requests.exceptions.SSLError:
        issues.append({"check": "ssl_expired", "detail": "Error SSL al conectar — certificado problemático", "evidence": "El navegador mostraría advertencia de seguridad al cliente"})
    except Exception:
        pass

    return issues


def check_admin_paths(url: str) -> list:
    """Busca paneles de administración expuestos."""
    issues = []
    if not HAS_REQUESTS:
        return issues

    admin_paths = ["/wp-admin", "/wp-login.php", "/admin", "/administrator",
                   "/login", "/cms", "/dashboard", "/panel"]
    found = []

    base = url.rstrip("/")
    for path in admin_paths:
        try:
            resp = requests.get(f"{base}{path}", timeout=5, verify=False,
                                allow_redirects=False)
            if resp.status_code in (200, 302, 301):
                found.append(f"{path} → HTTP {resp.status_code}")
        except Exception:
            pass

    if found:
        issues.append({
            "check": "admin_exposed",
            "detail": f"Panel de administración accesible desde internet: {', '.join(found[:3])}",
            "evidence": "Un atacante puede intentar acceder con credenciales por defecto o fuerza bruta",
        })

    return issues


# ── Motor de puntuación y clasificación ───────────────────────────────────────

def score_findings(findings: list) -> dict:
    """Calcula riesgo legal y puntuación."""
    grave_count = sum(1 for f in findings if LEGAL_REFS.get(f["check"], ("","leve",""))[1] == "grave")
    leve_count  = sum(1 for f in findings if LEGAL_REFS.get(f["check"], ("","leve",""))[1] == "leve")
    total = len(findings)

    if grave_count >= 2:
        risk_level = "ALTO"
        risk_color = "🔴"
        fine_range = RGPD_FINES["grave"]
    elif grave_count >= 1 or leve_count >= 3:
        risk_level = "MEDIO"
        risk_color = "🟠"
        fine_range = RGPD_FINES["leve"]
    elif total > 0:
        risk_level = "BAJO"
        risk_color = "🟡"
        fine_range = RGPD_FINES["leve"]
    else:
        risk_level = "MÍNIMO"
        risk_color = "🟢"
        fine_range = ("—", "")

    return {
        "total": total,
        "grave": grave_count,
        "leve": leve_count,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "fine_range": fine_range,
    }


# ── Generador de informe PDF para pymes ───────────────────────────────────────

def generate_sme_report(url: str, client_name: str, findings: list, score: dict, output_path: Path):
    """Genera PDF de diagnóstico en lenguaje no técnico para pymes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
    except ImportError:
        warn("reportlab no instalado: pip install reportlab")
        return None

    # Paleta
    PURPLE  = HexColor('#3B0764')
    PURPLE2 = HexColor('#7E22CE')
    RED     = HexColor('#DC2626')
    ORANGE  = HexColor('#EA580C')
    YELLOW  = HexColor('#D97706')
    GREEN   = HexColor('#16A34A')
    GRAY    = HexColor('#F3F4F6')
    DARK    = HexColor('#111827')
    MID     = HexColor('#6B7280')
    WHITE   = colors.white

    W, H = A4
    CW = W - 4.4*cm

    def add_hf(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(PURPLE)
        canvas.rect(0, H - 1.1*cm, W, 1.1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 7.5)
        canvas.drawString(2.2*cm, H - 0.68*cm, "INFORME DE DIAGNÓSTICO DE SEGURIDAD DIGITAL")
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(HexColor('#C4B5FD'))
        canvas.drawRightString(W - 2.2*cm, H - 0.68*cm, f"Purple Team Security  ·  Confidencial")
        canvas.setFillColor(HexColor('#F3F4F6'))
        canvas.rect(0, 0, W, 0.9*cm, fill=1, stroke=0)
        canvas.setFillColor(MID)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(2.2*cm, 0.33*cm, f"Diagnóstico realizado el {datetime.now().strftime('%d/%m/%Y')}")
        canvas.drawCentredString(W/2, 0.33*cm, f"Página {doc.page}")
        canvas.drawRightString(W - 2.2*cm, 0.33*cm, "Este informe es confidencial")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
        topMargin=1.5*cm, bottomMargin=1.2*cm,
        leftMargin=2.2*cm, rightMargin=2.2*cm)

    s = getSampleStyleSheet()
    def sty(name, **kw):
        return ParagraphStyle(name, **kw)

    story = []
    host = urlparse(url).hostname or url
    risk_colors_map = {"ALTO": RED, "MEDIO": ORANGE, "BAJO": YELLOW, "MÍNIMO": GREEN}
    rc = risk_colors_map.get(score["risk_level"], ORANGE)

    # ── PORTADA ──────────────────────────────────────────────────────────────
    cover = Table([['']], colWidths=[CW], rowHeights=[3.5*cm])
    cover.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PURPLE),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),[8,8,0,0])]))
    story.append(cover)

    inner = [
        [Paragraph("DIAGNÓSTICO DE SEGURIDAD DIGITAL", sty('ct', fontName='Helvetica', fontSize=9.5, textColor=HexColor('#C4B5FD'), alignment=TA_LEFT))],
        [Paragraph(client_name, sty('cn', fontName='Helvetica-Bold', fontSize=22, textColor=WHITE, alignment=TA_LEFT, leading=26))],
        [Paragraph(host, sty('ch', fontName='Helvetica', fontSize=11, textColor=HexColor('#DDD6FE'), alignment=TA_LEFT))],
        [Spacer(1, 0.4*cm)],
        [Paragraph(f"Análisis realizado: {datetime.now().strftime('%d de %B de %Y')}", sty('cd', fontName='Helvetica', fontSize=9, textColor=HexColor('#A78BFA'), alignment=TA_LEFT))],
    ]
    inner_t = Table(inner, colWidths=[CW])
    inner_t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PURPLE),
        ('TOPPADDING',(0,0),(0,0),18),('BOTTOMPADDING',(0,-1),(0,-1),20),
        ('LEFTPADDING',(0,0),(-1,-1),14),('TOPPADDING',(0,1),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-2),4),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),[0,0,8,8])]))
    story.append(inner_t)
    story.append(Spacer(1, 0.5*cm))

    # Semáforo de riesgo
    traffic_data = [[
        Paragraph(score["risk_color"], sty('ri', fontName='Helvetica-Bold', fontSize=28, alignment=TA_CENTER)),
        Paragraph(f"<b>NIVEL DE RIESGO: {score['risk_level']}</b>",
                  sty('rl', fontName='Helvetica-Bold', fontSize=14, textColor=rc, alignment=TA_LEFT)),
        Paragraph(f"<b>{score['fine_range'][0]}</b>\n{score['fine_range'][1]}",
                  sty('rf', fontName='Helvetica', fontSize=9, textColor=MID, alignment=TA_RIGHT)),
    ]]
    traffic_t = Table(traffic_data, colWidths=[1.5*cm, CW - 6*cm, 4.3*cm])
    traffic_t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),GRAY),
        ('TOPPADDING',(0,0),(-1,-1),12),('BOTTOMPADDING',(0,0),(-1,-1),12),
        ('LEFTPADDING',(0,0),(-1,-1),12),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('GRID',(0,0),(-1,-1),0.3,HexColor('#E5E7EB')),
        ('LINEABOVE',(0,0),(-1,0),3,rc),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),[4,4,4,4])]))
    story.append(traffic_t)
    story.append(Spacer(1, 0.4*cm))

    # Métricas
    met_data = [
        [Paragraph(str(score['total']), sty('m1', fontName='Helvetica-Bold', fontSize=24, textColor=PURPLE2, alignment=TA_CENTER)),
         Paragraph(str(score['grave']), sty('m2', fontName='Helvetica-Bold', fontSize=24, textColor=RED, alignment=TA_CENTER)),
         Paragraph(str(score['leve']),  sty('m3', fontName='Helvetica-Bold', fontSize=24, textColor=ORANGE, alignment=TA_CENTER))],
        [Paragraph("PROBLEMAS\nDETECTADOS", sty('ml1', fontName='Helvetica', fontSize=7.5, textColor=MID, alignment=TA_CENTER)),
         Paragraph("RIESGO\nGRAVE", sty('ml2', fontName='Helvetica', fontSize=7.5, textColor=MID, alignment=TA_CENTER)),
         Paragraph("RIESGO\nMODERADO", sty('ml3', fontName='Helvetica', fontSize=7.5, textColor=MID, alignment=TA_CENTER))],
    ]
    cw3 = CW/3
    met_t = Table(met_data, colWidths=[cw3]*3)
    met_t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),WHITE),
        ('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('GRID',(0,0),(-1,-1),0.4,HexColor('#E5E7EB')),
        ('LINEABOVE',(0,0),(-1,0),2,PURPLE2),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),[0,0,4,4])]))
    story.append(met_t)
    story.append(Spacer(1, 0.5*cm))

    # Intro no técnica
    intro_text = (
        f"Este informe recoge los resultados de un diagnóstico automatizado de seguridad digital "
        f"realizado sobre la presencia online de <b>{client_name}</b>. "
        f"El análisis evalúa el cumplimiento de la normativa vigente en materia de "
        f"<b>protección de datos (RGPD)</b>, seguridad en comunicaciones y buenas prácticas digitales. "
        f"Los problemas detectados no implican que haya habido ninguna intrusión, "
        f"pero sí representan vulnerabilidades que podrían ser aprovechadas y que, "
        f"en caso de incidente, constituirían <b>incumplimientos sancionables por la AEPD</b>."
    )
    story.append(Paragraph(intro_text, sty('intro', fontName='Helvetica', fontSize=10,
        textColor=DARK, leading=16, alignment=TA_JUSTIFY, spaceAfter=8)))
    story.append(PageBreak())

    # ── SECCIÓN: PROBLEMAS DETECTADOS ─────────────────────────────────────────
    def sec_hdr(title):
        t = Table([[Paragraph(title, sty('sh', fontName='Helvetica-Bold', fontSize=13,
            textColor=PURPLE, spaceBefore=4, spaceAfter=4))]], colWidths=[CW])
        t.setStyle(TableStyle([('LINEBELOW',(0,0),(-1,-1),2,PURPLE2),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
        return t

    story.append(sec_hdr("¿QUÉ HEMOS ENCONTRADO?"))
    story.append(Spacer(1, 0.3*cm))

    if not findings:
        story.append(Paragraph("✅ No se detectaron problemas significativos en este análisis.",
            sty('nf', fontName='Helvetica', fontSize=10, textColor=GREEN)))
    else:
        for i, f in enumerate(findings, 1):
            ref = LEGAL_REFS.get(f["check"], ("RGPD Art. 32", "leve", f["detail"]))
            severity = ref[1]
            sev_color = RED if severity == "grave" else ORANGE
            sev_label = "RIESGO GRAVE" if severity == "grave" else "RIESGO MODERADO"

            # Título del hallazgo
            hdr_row = [[
                Paragraph(f"<b>{i:02d}</b>", sty(f'fn{i}', fontName='Helvetica-Bold', fontSize=10,
                    textColor=sev_color, alignment=TA_CENTER)),
                Paragraph(f"<b>{_human_title(f['check'])}</b>",
                    sty(f'ft{i}', fontName='Helvetica-Bold', fontSize=10, textColor=DARK)),
                Paragraph(f"<b>{sev_label}</b>", sty(f'fs{i}', fontName='Helvetica-Bold',
                    fontSize=8, textColor=WHITE, alignment=TA_CENTER)),
            ]]
            hdr_t = Table(hdr_row, colWidths=[1.2*cm, CW - 4.2*cm, 2.8*cm])
            hdr_t.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,-1),HexColor('#FEF2F2') if severity=='grave' else HexColor('#FFF7ED')),
                ('BACKGROUND',(2,0),(2,0),sev_color),
                ('LINEBEFORE',(0,0),(0,-1),4,sev_color),
                ('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),
                ('LEFTPADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
                ('ROUNDEDCORNERS',(0,0),(-1,-1),[4,4,0,0])]))
            story.append(hdr_t)

            # Explicación y evidencia
            body_rows = [
                [Paragraph("<b>¿QUÉ SIGNIFICA?</b>", sty(f'bl{i}', fontName='Helvetica-Bold', fontSize=7.5, textColor=MID))],
                [Paragraph(ref[2], sty(f'bd{i}', fontName='Helvetica', fontSize=9.5, textColor=DARK, leading=14))],
                [Paragraph("<b>DETALLE TÉCNICO</b>", sty(f'el{i}', fontName='Helvetica-Bold', fontSize=7.5, textColor=MID))],
                [Paragraph(f.get("detail",""), sty(f'ed{i}', fontName='Helvetica', fontSize=9, textColor=HexColor('#374151'), leading=13))],
                [Paragraph("<b>REFERENCIA LEGAL</b>", sty(f'll{i}', fontName='Helvetica-Bold', fontSize=7.5, textColor=MID))],
                [Paragraph(ref[0], sty(f'ld{i}', fontName='Helvetica-Bold', fontSize=9, textColor=PURPLE2))],
            ]
            body_t = Table(body_rows, colWidths=[CW])
            body_t.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,-1),WHITE),
                ('TOPPADDING',(0,0),(0,0),6),('TOPPADDING',(0,1),(-1,1),2),
                ('BOTTOMPADDING',(0,1),(-1,1),6),('TOPPADDING',(0,2),(-1,2),4),
                ('TOPPADDING',(0,3),(-1,3),2),('BOTTOMPADDING',(0,3),(-1,3),6),
                ('TOPPADDING',(0,4),(-1,4),4),('TOPPADDING',(0,5),(-1,5),2),
                ('BOTTOMPADDING',(0,5),(-1,5),8),
                ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
                ('LINEBELOW',(0,-1),(-1,-1),0.5,HexColor('#E5E7EB')),
                ('ROUNDEDCORNERS',(0,0),(-1,-1),[0,0,4,4])]))
            story.append(body_t)
            story.append(Spacer(1, 0.35*cm))

    story.append(Spacer(1, 0.3*cm))
    story.append(sec_hdr("¿QUÉ PUEDE PASAR SI NO SE SOLUCIONA?"))
    story.append(Spacer(1, 0.2*cm))

    consequences = [
        ("💶 Sanciones económicas", f"La AEPD puede imponer multas de {RGPD_FINES['grave'][0]} ({RGPD_FINES['grave'][1]}) por incumplimiento del RGPD. Las pymes y autónomos no están exentos — existen multas publicadas a negocios pequeños por exactamente estos motivos."),
        ("📰 Daño reputacional", "Una brecha de seguridad o una multa de la AEPD puede aparecer en medios. Para un restaurante o negocio local, la pérdida de confianza de los clientes tiene un impacto directo en la facturación."),
        ("⚠️  Responsabilidad civil", "Si un cliente sufre un perjuicio por el robo de sus datos (número de tarjeta, datos de reserva, email), puede reclamar daños y perjuicios al negocio responsable de la custodia de esos datos."),
        ("🦠 Robo de datos en el local", "Un atacante en la red WiFi del restaurante puede interceptar los datos que circulan entre los clientes y la web (menús, reservas, pagos) si la conexión no está correctamente cifrada."),
    ]
    for title, desc in consequences:
        row = [[
            Paragraph(f"<b>{title}</b>", sty('ct2', fontName='Helvetica-Bold', fontSize=10, textColor=DARK, spaceAfter=3)),
            Paragraph(desc, sty('cd2', fontName='Helvetica', fontSize=9.5, textColor=DARK, leading=14)),
        ]]
        ct = Table(row, colWidths=[4*cm, CW - 4*cm])
        ct.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,-1),GRAY),
            ('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10),
            ('LEFTPADDING',(0,0),(-1,-1),10),('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LINEBELOW',(0,0),(-1,-1),0.4,HexColor('#E5E7EB'))]))
        story.append(ct)

    story.append(Spacer(1, 0.5*cm))
    story.append(sec_hdr("PRÓXIMOS PASOS RECOMENDADOS"))
    story.append(Spacer(1, 0.2*cm))

    cta_text = (
        f"Los problemas detectados en la web de <b>{client_name}</b> tienen solución. "
        f"La mayoría son configuraciones que un técnico especializado puede corregir en poco tiempo, "
        f"eliminando el riesgo legal y mejorando la seguridad de los datos de sus clientes. "
        f"Desde <b>Purple Team Security</b> ofrecemos un servicio de <b>auditoría y remediación completa</b> "
        f"adaptado al tamaño y presupuesto de su negocio, con certificación de cumplimiento RGPD "
        f"incluida una vez resueltos los problemas."
    )
    story.append(Paragraph(cta_text, sty('cta', fontName='Helvetica', fontSize=10,
        textColor=DARK, leading=16, alignment=TA_JUSTIFY, spaceAfter=10)))

    # Llamada a la acción
    cta_box = Table([[Paragraph(
        "📞 ¿Le interesa resolver estos problemas? Contáctenos para una reunión sin compromiso.",
        sty('ctab', fontName='Helvetica-Bold', fontSize=10, textColor=WHITE, alignment=TA_CENTER)
    )]], colWidths=[CW])
    cta_box.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),PURPLE2),
        ('TOPPADDING',(0,0),(-1,-1),14),('BOTTOMPADDING',(0,0),(-1,-1),14),
        ('ROUNDEDCORNERS',(0,0),(-1,-1),[6,6,6,6])]))
    story.append(cta_box)
    story.append(Spacer(1, 0.4*cm))

    # Disclaimer
    disclaimer = (
        "Este diagnóstico se ha realizado mediante análisis automatizado pasivo de la información "
        "públicamente accesible. No se ha accedido a ningún sistema interno ni se han modificado datos. "
        "El análisis es orientativo y no constituye una auditoría de seguridad completa. "
        "Purple Team Security actúa de acuerdo con la legislación vigente y el Código Ético del sector."
    )
    story.append(Paragraph(disclaimer, sty('dis', fontName='Helvetica-Oblique', fontSize=7.5,
        textColor=MID, leading=12, alignment=TA_JUSTIFY)))

    doc.build(story, onFirstPage=add_hf, onLaterPages=add_hf)
    return output_path


def _human_title(check_key: str) -> str:
    """Convierte claves técnicas a títulos entendibles por no técnicos."""
    titles = {
        "no_https":       "La web no usa conexión segura (sin HTTPS)",
        "ssl_expired":    "El certificado de seguridad está caducado",
        "ssl_weak":       "El certificado de seguridad expira pronto",
        "no_cookies":     "No hay aviso de cookies ni consentimiento",
        "no_privacy":     "Falta la Política de Privacidad",
        "form_insecure":  "Formularios de datos sin protección",
        "info_disclosure":"Información técnica interna expuesta",
        "admin_exposed":  "Panel de administración accesible desde internet",
        "http_headers":   "Protecciones web básicas no configuradas",
        "qr_mitm":        "El código QR puede ser interceptado en la red del local",
    }
    return titles.get(check_key, check_key.replace("_", " ").title())


# ── Flujo principal ────────────────────────────────────────────────────────────

def run_prospect_scan(url: str, client_name: str, output_dir: Path) -> dict:
    print(BANNER)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    host = urlparse(url).hostname or url
    print(f"{C.PURPLE}{C.BOLD}  Cliente: {client_name}  ·  URL: {url}{C.END}\n")

    all_findings = []
    t0 = time.time()

    hdr("Verificando conexión segura (HTTPS/SSL)...")
    f = check_https(url)
    all_findings.extend(f)
    ok(f"SSL/HTTPS: {len(f)} problema(s)") if f else ok("SSL/HTTPS: sin problemas")

    hdr("Analizando cabeceras de seguridad y RGPD...")
    f = check_http_headers(url)
    all_findings.extend(f)
    ok(f"Cabeceras/RGPD: {len(f)} problema(s)") if f else ok("Cabeceras/RGPD: sin problemas")

    hdr("Buscando paneles de administración expuestos...")
    f = check_admin_paths(url)
    all_findings.extend(f)
    bad(f"Admin expuesto: {len(f)} ruta(s) accesibles") if f else ok("Paneles admin: no expuestos")

    score = score_findings(all_findings)
    elapsed = time.time() - t0

    print(f"\n{C.BOLD}{'─'*55}{C.END}")
    print(f"  {score['risk_color']} Riesgo: {C.BOLD}{score['risk_level']}{C.END}  |  "
          f"Problemas: {score['total']} ({score['grave']} graves, {score['leve']} moderados)")
    print(f"  Posible multa RGPD: {C.RED}{score['fine_range'][0]}{C.END} {score['fine_range'][1]}")
    print(f"  Tiempo análisis: {elapsed:.0f}s")
    print(f"{C.BOLD}{'─'*55}{C.END}\n")

    # Generar PDF
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = client_name.replace(" ", "_").replace("/", "-")
    pdf_path = output_dir / f"Diagnostico_{safe}_{ts}.pdf"

    info("Generando informe PDF...")
    result = generate_sme_report(url, client_name, all_findings, score, pdf_path)
    if result:
        ok(f"Informe generado: {pdf_path.name}")
    else:
        warn("No se pudo generar el PDF (instala reportlab)")

    # JSON de sesión
    data = {
        "client": client_name, "url": url, "timestamp": datetime.now().isoformat(),
        "score": score, "findings": all_findings,
        "pdf": str(pdf_path) if result else None,
    }
    json_path = output_dir / f"diagnostico_{safe}_{ts}.json"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    ok(f"Datos guardados: {json_path.name}")

    return data


def main():
    parser = argparse.ArgumentParser(
        description="Purple Team - Prospecting Scanner (diagnóstico rápido para prospectos)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python prospect_scan.py --url https://restaurante.com
  python prospect_scan.py --url https://bar.es --client "Bar El Sol"
  python prospect_scan.py --url http://pizzeria.es --client "Pizzería Roma" --output ./prospectos/
        """
    )
    parser.add_argument("--url",    required=True, help="URL del negocio a analizar")
    parser.add_argument("--client", default="",    help="Nombre del cliente/negocio")
    parser.add_argument("--output", default="",    help="Directorio de salida")
    args = parser.parse_args()

    client_name = args.client or urlparse(args.url).hostname or args.url

    output_dir = Path(args.output) if args.output else (
        Path.home() / "storage" / "shared" / "Documents" / "purple_team_prospectos"
        if (Path.home() / "storage" / "shared").exists()
        else Path.home() / "Documents" / "purple_team_prospectos"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    run_prospect_scan(args.url, client_name, output_dir)


if __name__ == "__main__":
    main()
