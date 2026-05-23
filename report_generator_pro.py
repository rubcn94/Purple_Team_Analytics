# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║       PURPLE TEAM SUITE - PROFESSIONAL REPORT GENERATOR      ║
║       PDF con branding · Executive Summary · Gráficas        ║
║                                                              ║
║  Genera informes PDF profesionales a partir de los JSON      ║
║  producidos por los módulos de auditoría.                    ║
║                                                              ║
║  Uso:                                                        ║
║    python report_generator_pro.py --session ./sessions/XYZ/  ║
║    python report_generator_pro.py --session ./sessions/XYZ/ --client "Empresa SA" ║
║    python report_generator_pro.py --json results.json --type executive ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from collections import Counter

# ── Colores terminal ──────────────────────────────────────────────────────────
class C:
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    CYAN = '\033[96m'; BOLD = '\033[1m'; END = '\033[0m'

def ok(m):   print(f"{C.GREEN}  ✅  {m}{C.END}")
def info(m): print(f"{C.CYAN}  ℹ️   {m}{C.END}")
def warn(m): print(f"{C.YELLOW}  ⚠️   {m}{C.END}")


def check_reportlab():
    try:
        from reportlab.lib.pagesizes import A4
        return True
    except ImportError:
        print(f"\n  {C.YELLOW}⚠️  reportlab no instalado.{C.END}")
        print(f"  Instalar con: pip install reportlab --break-system-packages")
        print(f"  O en Termux:  pip install reportlab\n")
        return False


# ─── Generador PDF Profesional ────────────────────────────────────────────────
class ProfessionalReportGenerator:

    # Paleta de colores corporativa Purple Team
    PURPLE      = (82/255,  26/255, 139/255)
    PURPLE_DARK = (50/255,  10/255, 100/255)
    PURPLE_LIGHT= (180/255, 130/255, 220/255)
    RED_RISK    = (200/255,  40/255,  40/255)
    ORANGE_RISK = (230/255, 120/255,   0/255)
    YELLOW_RISK = (200/255, 180/255,   0/255)
    GREEN_OK    = ( 30/255, 160/255,  60/255)
    GRAY_LIGHT  = (0.95, 0.95, 0.95)
    GRAY_MID    = (0.75, 0.75, 0.75)
    WHITE       = (1.0, 1.0, 1.0)
    BLACK       = (0.0, 0.0, 0.0)
    DARK_TEXT   = (0.15, 0.15, 0.15)

    SEVERITY_COLORS = {
        "critical": (200/255, 40/255, 40/255),
        "high":     (230/255, 120/255, 0/255),
        "medium":   (200/255, 180/255, 0/255),
        "low":      (30/255, 160/255, 60/255),
        "info":     (70/255, 130/255, 200/255),
    }

    def __init__(self, session_dir=None, json_files=None, client_name="Cliente",
                 company_name="Purple Team Security", report_type="full"):
        self.session_dir = Path(session_dir) if session_dir else None
        self.json_files = json_files or []
        self.client_name = client_name
        self.company_name = company_name
        self.report_type = report_type
        self.data = {}
        self.all_findings = []
        self._load_data()

    def _load_data(self):
        """Carga todos los JSON de la sesión."""
        files_to_load = []
        if self.session_dir and self.session_dir.exists():
            files_to_load = list(self.session_dir.glob("**/*.json"))
        files_to_load.extend([Path(f) for f in self.json_files])

        for f in files_to_load:
            try:
                with open(f, 'r', encoding='utf-8') as fp:
                    content = json.load(fp)
                    module = f.stem.split('_')[0] if '_' in f.stem else f.stem
                    self.data[module] = content

                    # results_full.json: hallazgos anidados en content["results"][modulo]
                    if isinstance(content, dict) and "results" in content and isinstance(content["results"], dict):
                        for mod_name, mod_data in content["results"].items():
                            if isinstance(mod_data, dict):
                                self.data[mod_name] = mod_data
                                self._extract_findings(mod_data, mod_name)
                    else:
                        self._extract_findings(content, module)
            except Exception:
                pass
        self._deduplicate_findings()

    def _strip_ansi(self, text):
        return re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', str(text))

    def _is_junk_finding(self, text):
        """Descarta fragmentos JSON y contadores que no son hallazgos reales."""
        t = text.strip()
        if re.match(r'^"[a-z_]+"\s*:\s*', t):
            return True
        if re.match(r'^(Summary|Total|Score|Risk):', t, re.IGNORECASE):
            return True
        return False

    def _make_title(self, text, module):
        """Extrae un título limpio del texto del hallazgo."""
        clean = self._strip_ansi(text).strip()
        # Formato scanner: [HIGH ] 200 0B text/html /wp-admin
        m = re.search(r'\[(?:HIGH|MEDIUM|LOW|CRITICAL|INFO)\s*\]\s*\d+\s+\S+\s+\S+\s+(\S+)', clean)
        if m:
            path = m.group(1)
            if module in ("directories", "analysis"):
                return f"Ruta expuesta: {path}"
            return path
        return clean[:100]

    def _infer_severity(self, text):
        t = str(text).upper()
        if any(k in t for k in ["CRÍTICO", "CRITICO", "CRITICAL"]):
            return "critical"
        if any(k in t for k in ["ALTO", "HIGH"]):
            return "high"
        if any(k in t for k in ["MEDIO", "MEDIUM", "WARN", "MODERADO"]):
            return "medium"
        if any(k in t for k in ["BAJO", "LOW", "INFO"]):
            return "low"
        return "info"

    def _normalize_finding(self, item, module, key):
        """Convierte cualquier formato de hallazgo a dict normalizado."""
        if isinstance(item, dict):
            # Blue Team format: {"module": ..., "finding": "texto"}
            if "finding" in item and "title" not in item:
                raw = item["finding"]
                if self._is_junk_finding(self._strip_ansi(raw)):
                    return None
                clean = self._strip_ansi(raw)
                item["title"] = self._make_title(raw, item.get("module", module))
                item["description"] = clean
                if "severity" not in item:
                    item["severity"] = self._infer_severity(raw)
            if "severity" not in item:
                title = item.get("title", item.get("name", str(item)))
                item["severity"] = self._infer_severity(title)
            item.setdefault("_source_module", module)
            item.setdefault("_source_key", key)
            return item
        elif isinstance(item, str) and item.strip():
            raw = item
            if self._is_junk_finding(self._strip_ansi(raw)):
                return None
            clean = self._strip_ansi(raw)
            return {
                "title": self._make_title(raw, module),
                "description": clean,
                "severity": self._infer_severity(raw),
                "_source_module": module,
                "_source_key": key,
            }
        return None

    def _extract_findings(self, data, module):
        """Extrae hallazgos en formato normalizado."""
        # Evitar re-agregar all_findings del módulo analysis (ya vienen de los módulos individuales)
        if module == "analysis":
            return
        finding_keys = [
            "findings", "vulnerabilities", "issues", "ioc_findings",
            "hardening_findings", "exposed_assets", "log_anomalies",
            "network_anomalies", "email_breaches", "all_findings", "alerts",
        ]
        for key in finding_keys:
            items = data.get(key, [])
            if not isinstance(items, list):
                continue
            for item in items:
                normalized = self._normalize_finding(item, module, key)
                if normalized:
                    self.all_findings.append(normalized)

    def _deduplicate_findings(self):
        seen = set()
        deduped = []
        for f in self.all_findings:
            key = self._strip_ansi(f.get('description', f.get('title', str(f))))[:120]
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        self.all_findings = deduped

    def _severity_sort_key(self, f):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(f.get("severity", "info"), 5)

    # ──────────────────────────────────────────────────────────────────────────
    def generate(self, output_path=None):
        """Genera el informe PDF profesional."""
        if not check_reportlab():
            return None

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                        TableStyle, PageBreak, HRFlowable, KeepTogether)
        from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
        from reportlab.lib import colors

        W, H = A4

        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            client_safe = self.client_name.replace(' ', '_').replace('/', '-')
            if self.session_dir:
                output_path = self.session_dir / f"INFORME_{client_safe}_{ts}.pdf"
            else:
                output_path = Path.home() / "Documents" / f"INFORME_{client_safe}_{ts}.pdf"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        def rc(t): return colors.Color(t[0], t[1], t[2])

        C_PURPLE      = rc(self.PURPLE)
        C_PURPLE_DARK = rc(self.PURPLE_DARK)
        C_PURPLE_LIGHT= rc(self.PURPLE_LIGHT)
        C_RED         = rc(self.RED_RISK)
        C_ORANGE      = rc(self.ORANGE_RISK)
        C_YELLOW      = rc(self.YELLOW_RISK)
        C_GREEN       = rc(self.GREEN_OK)
        C_WHITE       = rc(self.WHITE)
        C_BLACK       = rc(self.BLACK)
        C_DARK        = rc(self.DARK_TEXT)
        C_GRAY_L      = rc(self.GRAY_LIGHT)
        C_GRAY_M      = rc(self.GRAY_MID)
        C_NAVY        = colors.HexColor('#1a1a2e')
        C_ACCENT      = colors.HexColor('#f0f0f8')

        SEV_COLORS = {
            "critical": C_RED, "high": C_ORANGE,
            "medium": C_YELLOW, "low": C_GREEN, "info": rc((0.27, 0.51, 0.78)),
        }
        SEV_LABELS = {"critical": "CRÍTICO", "high": "ALTO",
                      "medium": "MEDIO", "low": "BAJO", "info": "INFO"}

        ts_str = datetime.now().strftime("%d/%m/%Y")

        # ── Footer en cada página ─────────────────────────────────────────────
        company = self.company_name
        client  = self.client_name

        def page_footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(C_PURPLE)
            canvas.setLineWidth(0.8)
            canvas.line(2*cm, 1.8*cm, W - 2*cm, 1.8*cm)
            canvas.setFont('Helvetica', 7)
            canvas.setFillColor(colors.HexColor('#666666'))
            canvas.drawString(2*cm, 1.3*cm, f"{company}  ·  Informe confidencial  ·  {client}")
            canvas.drawRightString(W - 2*cm, 1.3*cm, f"Página {doc.page}")
            canvas.restoreState()

        def cover_page(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(C_NAVY)
            canvas.rect(0, 0, W, H, fill=1, stroke=0)
            canvas.setFillColor(C_PURPLE)
            canvas.rect(0, H * 0.38, W, H * 0.62, fill=1, stroke=0)
            canvas.setFillColor(colors.Color(1, 1, 1, alpha=0.04))
            for i in range(0, int(W) + 60, 60):
                canvas.setLineWidth(0.3)
                canvas.setStrokeColor(colors.Color(1, 1, 1, alpha=0.06))
                canvas.line(i, H * 0.38, i, H)
            canvas.setFillColor(C_WHITE)
            canvas.setFont('Helvetica-Bold', 32)
            canvas.drawCentredString(W / 2, H * 0.72, "INFORME DE AUDITORÍA")
            canvas.setFont('Helvetica-Bold', 24)
            canvas.drawCentredString(W / 2, H * 0.66, "DE SEGURIDAD")
            canvas.setFillColor(C_PURPLE_LIGHT)
            canvas.setFont('Helvetica', 13)
            canvas.drawCentredString(W / 2, H * 0.60, "Purple Team Security Assessment")
            canvas.setFillColor(C_WHITE)
            canvas.setFont('Helvetica', 10)
            canvas.drawCentredString(W / 2, H * 0.54, ts_str)
            canvas.setFillColor(colors.Color(1, 1, 1, alpha=0.12))
            canvas.rect(1.5*cm, H * 0.10, W - 3*cm, H * 0.26, fill=1, stroke=0)
            canvas.setFillColor(C_WHITE)
            canvas.setFont('Helvetica-Bold', 10)
            canvas.drawString(2.5*cm, H * 0.32, "Cliente:")
            canvas.drawString(2.5*cm, H * 0.27, "Preparado por:")
            canvas.drawString(2.5*cm, H * 0.22, "Clasificación:")
            canvas.drawString(2.5*cm, H * 0.17, "Tipo de informe:")
            canvas.setFont('Helvetica', 10)
            canvas.drawString(6.5*cm, H * 0.32, client)
            canvas.drawString(6.5*cm, H * 0.27, company)
            canvas.drawString(6.5*cm, H * 0.22, "CONFIDENCIAL — USO INTERNO")
            canvas.drawString(6.5*cm, H * 0.17, "Purple Team Full Assessment")
            canvas.setFillColor(C_RED)
            canvas.roundRect(W - 5.5*cm, H * 0.20, 3.8*cm, 0.7*cm, 4, fill=1, stroke=0)
            canvas.setFillColor(C_WHITE)
            canvas.setFont('Helvetica-Bold', 9)
            canvas.drawCentredString(W - 3.6*cm, H * 0.225, "CONFIDENCIAL")
            canvas.setFillColor(colors.HexColor('#888888'))
            canvas.setFont('Helvetica', 7.5)
            legal = ("Este documento contiene información confidencial de uso exclusivo para el destinatario. "
                     "Queda prohibida su reproducción o divulgación sin autorización expresa.")
            canvas.drawCentredString(W / 2, H * 0.055, legal)
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(output_path), pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2.8*cm,
            title=f"Informe de Auditoría — {self.client_name}",
            author=self.company_name,
        )

        styles = getSampleStyleSheet()

        def S(name, **kw):
            base = kw.pop('parent', styles['Normal'])
            return ParagraphStyle(name, parent=base, **kw)

        sH1    = S('H1',    fontSize=17, fontName='Helvetica-Bold',
                   textColor=C_NAVY, spaceBefore=16, spaceAfter=4)
        sH2    = S('H2',    fontSize=11, fontName='Helvetica-Bold',
                   textColor=C_PURPLE, spaceBefore=10, spaceAfter=4)
        sBody  = S('Body',  fontSize=9.5, fontName='Helvetica',
                   textColor=C_DARK, leading=15, alignment=TA_JUSTIFY, spaceAfter=4)
        sSmall = S('Small', fontSize=8.5, fontName='Helvetica',
                   textColor=C_DARK, leading=12)
        sNote  = S('Note',  fontSize=8, fontName='Helvetica-Oblique',
                   textColor=colors.HexColor('#555555'), spaceAfter=4)
        sTocN  = S('TocN',  fontSize=10, fontName='Helvetica', textColor=C_DARK)
        sTocNu = S('TocNu', fontSize=10, fontName='Helvetica-Bold', textColor=C_PURPLE)
        sCover = S('Cover', fontSize=9, fontName='Helvetica', textColor=C_WHITE)

        def section_header(title):
            """Retorna lista de elementos para un encabezado de sección."""
            header = Table([[Paragraph(title, sH1)]], colWidths=[17*cm])
            header.setStyle(TableStyle([
                ('LEFTPADDING',   (0,0), (-1,-1), 12),
                ('TOPPADDING',    (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LINEBEFORE',    (0,0), (0,-1), 4, C_PURPLE),
                ('BACKGROUND',    (0,0), (-1,-1), C_ACCENT),
            ]))
            return [header, Spacer(1, 0.3*cm)]

        def bar_chart(values, labels, bar_colors):
            """Gráfico de barras manual con colores y etiquetas correctas."""
            d = Drawing(460, 170)
            max_v = max(list(values) + [1])
            bw, gap, base_y, start_x, ch = 68, 14, 28, 50, 120
            for i, (v, c, l) in enumerate(zip(values, bar_colors, labels)):
                x = start_x + i * (bw + gap)
                bh = max(2, int(v / max_v * ch)) if v > 0 else 0
                d.add(Rect(x, base_y, bw, bh, fillColor=c, strokeColor=None))
                d.add(Rect(x, base_y, bw, min(bh, 4), fillColor=colors.Color(0,0,0,0.15), strokeColor=None))
                d.add(String(x + bw/2, base_y - 14, l,
                             textAnchor='middle', fontSize=8.5, fontName='Helvetica',
                             fillColor=colors.HexColor('#333333')))
                if v > 0:
                    d.add(String(x + bw/2, base_y + bh + 4, str(v),
                                 textAnchor='middle', fontSize=9, fontName='Helvetica-Bold',
                                 fillColor=colors.HexColor('#333333')))
            ticks = 5
            for t in range(ticks + 1):
                y = base_y + t / ticks * ch
                val = int(max_v * t / ticks)
                d.add(String(start_x - 6, y - 3, str(val),
                             textAnchor='end', fontSize=7, fontName='Helvetica',
                             fillColor=colors.HexColor('#888888')))
                d.add(Line(start_x - 3, y, start_x + len(values) * (bw + gap) - gap, y,
                           strokeColor=colors.Color(0.85, 0.85, 0.85), strokeWidth=0.5))
            d.add(Line(start_x - 3, base_y,
                       start_x + len(values) * (bw + gap) - gap, base_y,
                       strokeColor=colors.HexColor('#999999'), strokeWidth=1))
            return d

        story = []

        # ── PORTADA (dibujada por cover_page callback) ────────────────────────
        story.append(Spacer(1, 0.1))
        story.append(PageBreak())

        # ── ÍNDICE ────────────────────────────────────────────────────────────
        story += section_header("ÍNDICE DE CONTENIDOS")
        toc_items = [
            ("1", "Resumen Ejecutivo"),
            ("2", "Metodología y Alcance"),
            ("3", "Métricas de Riesgo"),
            ("4", "Hallazgos Identificados"),
            ("5", "Análisis de Compliance"),
            ("6", "Plan de Remediación"),
            ("7", "Conclusiones y Siguientes Pasos"),
        ]
        toc_data = [[Paragraph(n, sTocNu), Paragraph(t, sTocN)] for n, t in toc_items]
        toc_table = Table(toc_data, colWidths=[1*cm, 16*cm])
        toc_table.setStyle(TableStyle([
            ('TOPPADDING',    (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LINEBELOW',     (0,0), (-1,-2), 0.4, C_GRAY_M),
            ('LEFTPADDING',   (0,0), (-1,-1), 4),
        ]))
        story.append(toc_table)
        story.append(PageBreak())

        # ── 1. RESUMEN EJECUTIVO ──────────────────────────────────────────────
        story += section_header("1.  RESUMEN EJECUTIVO")

        sev_counter = Counter(f.get("severity", "info") for f in self.all_findings)
        critical_n = sev_counter.get("critical", 0)
        high_n     = sev_counter.get("high", 0)
        medium_n   = sev_counter.get("medium", 0)
        low_n      = sev_counter.get("low", 0)
        total_n    = len(self.all_findings)

        if critical_n > 0:
            risk_level = "CRÍTICO"; risk_color = C_RED
        elif high_n > 2:
            risk_level = "ALTO";    risk_color = C_ORANGE
        elif high_n > 0 or medium_n > 3:
            risk_level = "MEDIO";   risk_color = C_YELLOW
        else:
            risk_level = "BAJO";    risk_color = C_GREEN

        story.append(Paragraph(
            f"Se ha realizado una auditoría de seguridad <b>Purple Team</b> para "
            f"<b>{self.client_name}</b>, abarcando reconocimiento externo, análisis de "
            f"vulnerabilidades, evaluación de controles defensivos y compliance normativo. "
            f"Se han identificado <b>{total_n} hallazgos</b> con nivel de riesgo global "
            f"<b>{risk_level}</b>.", sBody))
        story.append(Spacer(1, 0.4*cm))

        # KPI cards
        kpi_labels = ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]
        kpi_vals   = [critical_n, high_n, medium_n, low_n]
        kpi_colors = [C_RED, C_ORANGE, C_YELLOW, C_GREEN]
        kpi_cells  = []
        for lbl, val, col in zip(kpi_labels, kpi_vals, kpi_colors):
            cell = Table([
                [Paragraph(lbl, S('kL', fontSize=8, fontName='Helvetica-Bold',
                                  textColor=C_WHITE, alignment=TA_CENTER))],
                [Paragraph(str(val), S('kV', fontSize=28, fontName='Helvetica-Bold',
                                       textColor=C_WHITE, alignment=TA_CENTER))],
            ], colWidths=[4.0*cm])
            cell.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,-1), col),
                ('TOPPADDING',    (0,0), (-1,0),  10),
                ('BOTTOMPADDING', (0,1), (-1,-1), 12),
                ('TOPPADDING',    (0,1), (-1,-1), 4),
            ]))
            kpi_cells.append(cell)
        kpi_row = Table([kpi_cells], colWidths=[4.0*cm]*4,
                        hAlign='CENTER', rowHeights=[None])
        kpi_row.setStyle(TableStyle([
            ('LEFTPADDING',  (0,0), (-1,-1), 4),
            ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(kpi_row)
        story.append(Spacer(1, 0.4*cm))

        # Risk badge
        badge = Table([[Paragraph(f"▶  NIVEL DE RIESGO GLOBAL:  {risk_level}",
                                  S('RB', fontSize=13, fontName='Helvetica-Bold',
                                    textColor=C_WHITE, alignment=TA_CENTER))]],
                      colWidths=[17*cm])
        badge.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), risk_color),
            ('TOPPADDING',    (0,0), (-1,-1), 11),
            ('BOTTOMPADDING', (0,0), (-1,-1), 11),
        ]))
        story.append(badge)
        story.append(PageBreak())

        # ── 2. METODOLOGÍA ────────────────────────────────────────────────────
        story += section_header("2.  METODOLOGÍA Y ALCANCE")
        story.append(Paragraph(
            "La auditoría sigue el framework <b>MITRE ATT&CK</b> para la fase ofensiva y los "
            "controles <b>CIS Benchmark</b> / <b>NIST CSF</b> para la fase defensiva, "
            "estructurada en 7 fases:", sBody))
        story.append(Spacer(1, 0.25*cm))

        phases = [
            ("1", "Reconocimiento Pasivo (OSINT)", "Inteligencia en fuentes abiertas sin contacto con el objetivo."),
            ("2", "Reconocimiento Activo",          "Enumeración de servicios, puertos y tecnologías expuestas."),
            ("3", "Análisis de Vulnerabilidades",   "Identificación de CVEs, configuraciones inseguras y debilidades."),
            ("4", "Evaluación Defensiva",            "Verificación de hardening, logs y capacidades de detección."),
            ("5", "Evaluación de Compliance",        "Análisis de cumplimiento normativo: RGPD, ENS, PCI DSS."),
            ("6", "Análisis WiFi",                   "Evaluación de seguridad de la red inalámbrica."),
            ("7", "Reporting y Remediación",         "Informe con hallazgos priorizados y plan de acción."),
        ]
        ph_data = [
            [Paragraph("<b>Fase</b>", sSmall),
             Paragraph("<b>Nombre</b>", sSmall),
             Paragraph("<b>Descripción</b>", sSmall)]
        ] + [[Paragraph(n, S('PN', fontSize=8.5, fontName='Helvetica-Bold', textColor=C_PURPLE)),
              Paragraph(t, S('PT', fontSize=8.5, fontName='Helvetica-Bold', textColor=C_DARK)),
              Paragraph(d, sSmall)] for n, t, d in phases]
        ph_table = Table(ph_data, colWidths=[1.4*cm, 5*cm, 10.6*cm])
        ph_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0),  8.5),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_ACCENT]),
            ('LINEBELOW',     (0,0), (-1,-1), 0.4, C_GRAY_M),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(ph_table)
        story.append(PageBreak())

        # ── 3. MÉTRICAS DE RIESGO ─────────────────────────────────────────────
        story += section_header("3.  MÉTRICAS DE RIESGO")
        story.append(Paragraph("Distribución de hallazgos por nivel de severidad:", sH2))
        story.append(Spacer(1, 0.2*cm))

        chart = bar_chart(
            [critical_n, high_n, medium_n, low_n],
            ["Crítico", "Alto", "Medio", "Bajo"],
            [C_RED, C_ORANGE, C_YELLOW, C_GREEN]
        )
        story.append(chart)
        story.append(Spacer(1, 0.4*cm))

        # Tabla resumen de módulos
        mod_map = {"subdomain": "Subdominios", "ssl": "SSL/TLS",
                   "http": "HTTP Security", "directories": "Dir. Scanner", "cve": "CVE Correlator"}
        mod_rows = []
        sev_by_mod = {}
        for f in self.all_findings:
            m = f.get("module", f.get("_source_module", "other"))
            s = f.get("severity", "info")
            sev_by_mod.setdefault(m, Counter())[s] += 1

        for mod, counts in sorted(sev_by_mod.items()):
            label = mod_map.get(mod, mod.replace('_', ' ').title())
            total = sum(counts.values())
            worst = next((s for s in ("critical","high","medium","low","info") if counts.get(s,0) > 0), "info")
            mod_rows.append([
                Paragraph(label, sSmall),
                Paragraph(str(counts.get("critical",0)), S('MC', fontSize=8.5, fontName='Helvetica-Bold', textColor=C_RED, alignment=TA_CENTER)),
                Paragraph(str(counts.get("high",0)),     S('MH', fontSize=8.5, fontName='Helvetica-Bold', textColor=C_ORANGE, alignment=TA_CENTER)),
                Paragraph(str(counts.get("medium",0)),   S('MM', fontSize=8.5, fontName='Helvetica-Bold', textColor=colors.HexColor('#b8860b'), alignment=TA_CENTER)),
                Paragraph(str(counts.get("low",0)),      S('ML2', fontSize=8.5, fontName='Helvetica-Bold', textColor=C_GREEN, alignment=TA_CENTER)),
                Paragraph(str(total), S('MT', fontSize=8.5, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            ])

        if mod_rows:
            story.append(Paragraph("Hallazgos por módulo:", sH2))
            hdr = [Paragraph(h, S('TH', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE, alignment=TA_CENTER))
                   for h in ["Módulo", "Crítico", "Alto", "Medio", "Bajo", "Total"]]
            mod_table = Table([hdr] + mod_rows, colWidths=[6*cm, 2.2*cm, 2.2*cm, 2.2*cm, 2.2*cm, 2.2*cm])
            mod_table.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_ACCENT]),
                ('LINEBELOW',     (0,0), (-1,-1), 0.4, C_GRAY_M),
                ('TOPPADDING',    (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING',   (0,0), (0,-1),  10),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(mod_table)
        story.append(PageBreak())

        # ── 4. HALLAZGOS ─────────────────────────────────────────────────────
        story += section_header("4.  HALLAZGOS IDENTIFICADOS")
        sorted_findings = sorted(self.all_findings, key=self._severity_sort_key)

        if not sorted_findings:
            story.append(Paragraph("No se encontraron hallazgos significativos.", sBody))
        else:
            current_sev = None
            for i, finding in enumerate(sorted_findings[:60], 1):
                sev = finding.get("severity", "info")

                # Separador de grupo por severidad
                if sev != current_sev:
                    current_sev = sev
                    sev_c = SEV_COLORS.get(sev, C_GRAY_M)
                    sev_lbl = SEV_LABELS.get(sev, sev.upper())
                    grp = Table([[Paragraph(f"  {sev_lbl}", S('GL', fontSize=9,
                                  fontName='Helvetica-Bold', textColor=C_WHITE))]],
                                colWidths=[17*cm])
                    grp.setStyle(TableStyle([
                        ('BACKGROUND',    (0,0), (-1,-1), sev_c),
                        ('TOPPADDING',    (0,0), (-1,-1), 5),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                    ]))
                    story.append(Spacer(1, 0.2*cm))
                    story.append(grp)
                    story.append(Spacer(1, 0.1*cm))

                title   = self._strip_ansi(str(finding.get("title") or finding.get("type", "Hallazgo")))[:90]
                detail  = self._strip_ansi(str(finding.get("description", "")))[:350]
                source  = finding.get("module", finding.get("_source_module", ""))

                # Card: borde lateral + contenido blanco
                sev_c = SEV_COLORS.get(sev, C_GRAY_M)
                content_rows = [
                    [Paragraph(f"{i:02d}.  {title}",
                               S('FT', fontSize=9.5, fontName='Helvetica-Bold', textColor=C_DARK))]
                ]
                if detail and detail != title:
                    content_rows.append([Paragraph(detail, S('FD', fontSize=8.5,
                                         fontName='Helvetica', textColor=colors.HexColor('#444444'),
                                         leading=12))])
                if source:
                    content_rows.append([Paragraph(
                        f"Módulo: {source.title()}",
                        S('FS2', fontSize=7.5, fontName='Helvetica-Oblique',
                          textColor=colors.HexColor('#888888')))])

                content = Table(content_rows, colWidths=[15.6*cm])
                content.setStyle(TableStyle([
                    ('TOPPADDING',    (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING',   (0,0), (-1,-1), 8),
                    ('BACKGROUND',    (0,0), (-1,-1), C_WHITE),
                ]))

                card = Table([[None, content]], colWidths=[0.35*cm, 16.65*cm])
                card.setStyle(TableStyle([
                    ('BACKGROUND',    (0,0), (0,-1),  sev_c),
                    ('BACKGROUND',    (1,0), (1,-1),  C_WHITE),
                    ('TOPPADDING',    (0,0), (-1,-1), 0),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                    ('LEFTPADDING',   (0,0), (-1,-1), 0),
                    ('RIGHTPADDING',  (0,0), (-1,-1), 0),
                    ('LINEBELOW',     (0,0), (-1,-1), 0.5, C_GRAY_M),
                ]))
                story.append(card)

        story.append(PageBreak())

        # ── 5. COMPLIANCE ─────────────────────────────────────────────────────
        story += section_header("5.  ANÁLISIS DE COMPLIANCE NORMATIVO")
        compliance_data = self.data.get("compliance", {})
        if compliance_data:
            rgpd_score = compliance_data.get("rgpd", {}).get("score", 0)
            ens_score  = compliance_data.get("ens",  {}).get("score", 0)
            pci_score  = compliance_data.get("pci_dss", {}).get("score", 0)
            comp_rows  = [
                [Paragraph("<b>Normativa</b>", sSmall),
                 Paragraph("<b>Score</b>", S('CH', fontSize=8.5, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                 Paragraph("<b>Estado</b>", S('CH2', fontSize=8.5, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                 Paragraph("<b>Hallazgos</b>", S('CH3', fontSize=8.5, fontName='Helvetica-Bold', alignment=TA_CENTER))],
            ]
            for norm, score, flist in [
                ("RGPD / LOPD-GDD", rgpd_score, compliance_data.get("rgpd",{}).get("findings",[])),
                ("ENS",             ens_score,  compliance_data.get("ens",{}).get("findings",[])),
                ("PCI DSS",         pci_score,  compliance_data.get("pci_dss",{}).get("findings",[])),
            ]:
                st = "Conforme" if score >= 80 else ("Parcial" if score >= 60 else "No Conforme")
                sc = C_GREEN if score >= 80 else (C_ORANGE if score >= 60 else C_RED)
                comp_rows.append([
                    Paragraph(norm, sSmall),
                    Paragraph(f"{score}%", S('CS', fontSize=8.5, fontName='Helvetica-Bold',
                               textColor=sc, alignment=TA_CENTER)),
                    Paragraph(st, S('CSS', fontSize=8.5, fontName='Helvetica-Bold',
                               textColor=sc, alignment=TA_CENTER)),
                    Paragraph(str(len(flist)), S('CFN', fontSize=8.5, alignment=TA_CENTER)),
                ])
            comp_table = Table(comp_rows, colWidths=[6*cm, 3*cm, 5*cm, 3*cm])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
                ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_ACCENT]),
                ('LINEBELOW',     (0,0), (-1,-1), 0.4, C_GRAY_M),
                ('TOPPADDING',    (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING',   (0,0), (-1,-1), 10),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(comp_table)
        else:
            story.append(Paragraph(
                "No se dispone de datos de compliance en esta sesión. "
                "Ejecute <i>compliance/compliance_checker.py</i> para obtener el análisis normativo.",
                sBody))
        story.append(PageBreak())

        # ── 6. PLAN DE REMEDIACIÓN ────────────────────────────────────────────
        story += section_header("6.  PLAN DE REMEDIACIÓN PRIORIZADO")
        story.append(Paragraph(
            "Los hallazgos se priorizan por criticidad. Los críticos deben resolverse en "
            "<b>72 horas</b>, los altos en <b>2 semanas</b> y los medios en el siguiente "
            "ciclo de mejora.", sBody))
        story.append(Spacer(1, 0.3*cm))

        tf = {"critical": "72 h", "high": "2 semanas", "medium": "1 mes", "low": "3 meses"}
        ef = {"critical": "Alto",  "high": "Medio-Alto", "medium": "Medio", "low": "Bajo"}

        rem_hdr = [Paragraph(h, S('RH', fontSize=8, fontName='Helvetica-Bold', textColor=C_WHITE,
                              alignment=TA_CENTER if h != "Hallazgo" else TA_LEFT))
                   for h in ["#", "Hallazgo", "Severidad", "Plazo", "Esfuerzo"]]
        rem_rows = [rem_hdr]
        for i, f in enumerate(sorted_findings[:25], 1):
            sev  = f.get("severity", "info")
            name = self._strip_ansi(str(f.get("title") or f.get("type", "Hallazgo")))[:50]
            sev_c = SEV_COLORS.get(sev, C_GRAY_M)
            rem_rows.append([
                Paragraph(str(i), S('RI', fontSize=8.5, alignment=TA_CENTER)),
                Paragraph(name,   S('RN', fontSize=8.5)),
                Paragraph(SEV_LABELS.get(sev, sev.upper()),
                          S('RS', fontSize=8, fontName='Helvetica-Bold',
                            textColor=sev_c, alignment=TA_CENTER)),
                Paragraph(tf.get(sev,"—"),  S('RT', fontSize=8.5, alignment=TA_CENTER)),
                Paragraph(ef.get(sev,"—"),  S('RE', fontSize=8.5, alignment=TA_CENTER)),
            ])
        rem_table = Table(rem_rows, colWidths=[0.8*cm, 8.5*cm, 2.4*cm, 2.4*cm, 2.9*cm])
        rem_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  C_NAVY),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_WHITE, C_ACCENT]),
            ('LINEBELOW',     (0,0), (-1,-1), 0.4, C_GRAY_M),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(rem_table)
        story.append(PageBreak())

        # ── 7. CONCLUSIONES ───────────────────────────────────────────────────
        story += section_header("7.  CONCLUSIONES Y SIGUIENTES PASOS")
        story.append(Paragraph(
            f"Tras el análisis realizado, <b>{self.client_name}</b> presenta un nivel de riesgo "
            f"<b>{risk_level}</b> con <b>{total_n} hallazgos</b> identificados "
            f"({critical_n} críticos, {high_n} altos, {medium_n} medios, {low_n} bajos). "
            f"Se recomienda abordar de forma inmediata los hallazgos críticos e implementar "
            f"un programa de seguridad continuo.", sBody))
        story.append(Spacer(1, 0.4*cm))

        steps = [
            ("Inmediato  (0–72 h)",   C_RED,    "Remediar todos los hallazgos críticos identificados en este informe."),
            ("Corto plazo  (2 sem.)", C_ORANGE, "Implementar controles de seguridad para los hallazgos de nivel alto."),
            ("Medio plazo  (1 mes)",  C_YELLOW, "Resolver hallazgos medios y configurar monitoreo continuo."),
            ("Largo plazo  (3 mes.)", C_GREEN,  "Auditoría de seguimiento para verificar todas las remediaciones."),
            ("Continuo",              C_PURPLE, "Programa de formación en ciberseguridad para el personal."),
        ]
        for plazo, col, accion in steps:
            row = Table([[
                Table([[Paragraph(plazo, S('SP', fontSize=8, fontName='Helvetica-Bold',
                                          textColor=C_WHITE, alignment=TA_CENTER))]],
                      colWidths=[3.2*cm],
                      style=TableStyle([('BACKGROUND',(0,0),(-1,-1),col),
                                        ('TOPPADDING',(0,0),(-1,-1),8),
                                        ('BOTTOMPADDING',(0,0),(-1,-1),8)])),
                Paragraph(accion, S('SA', fontSize=9, fontName='Helvetica',
                                    textColor=C_DARK)),
            ]], colWidths=[3.4*cm, 13.6*cm])
            row.setStyle(TableStyle([
                ('LINEBELOW',     (0,0), (-1,-1), 0.5, C_GRAY_M),
                ('TOPPADDING',    (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                ('LEFTPADDING',   (1,0), (1,-1),  10),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
                ('BACKGROUND',    (1,0), (1,-1),  C_WHITE),
            ]))
            story.append(row)

        story.append(Spacer(1, 0.8*cm))
        final = Table([[Paragraph(
            f"{self.company_name}  ·  Purple Team Security Assessment  ·  {ts_str}",
            S('FN', fontSize=8, fontName='Helvetica', textColor=C_WHITE, alignment=TA_CENTER))]],
            colWidths=[17*cm])
        final.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), C_NAVY),
            ('TOPPADDING',    (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(final)

        info("Generando PDF profesional...")
        doc.build(story,
                  onFirstPage=cover_page,
                  onLaterPages=page_footer)
        ok(f"Informe PDF generado: {output_path}")
        return str(output_path)


# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Report Generator Pro — Informes PDF profesionales")
    parser.add_argument("--session", help="Directorio de sesión con los JSON de resultados")
    parser.add_argument("--json", nargs='+', help="Archivos JSON específicos")
    parser.add_argument("--client", default="Cliente", help="Nombre del cliente")
    parser.add_argument("--company", default="Purple Team Security", help="Nombre de la empresa auditora")
    parser.add_argument("--output", help="Ruta del PDF de salida")
    parser.add_argument("--type", choices=["full", "executive", "technical"],
                        default="full", help="Tipo de informe")
    args = parser.parse_args()

    if not args.session and not args.json:
        print("  Uso: python report_generator_pro.py --session ./sessions/YYYY-MM-DD/")
        print("  O:   python report_generator_pro.py --json results.json --client 'Empresa'")
        sys.exit(1)

    generator = ProfessionalReportGenerator(
        session_dir=args.session,
        json_files=args.json or [],
        client_name=args.client,
        company_name=args.company,
        report_type=args.type
    )
    generator.generate(output_path=args.output)


if __name__ == "__main__":
    main()
