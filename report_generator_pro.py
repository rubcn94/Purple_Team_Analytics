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
                    # Extraer hallazgos normalizados
                    self._extract_findings(content, module)
            except Exception:
                pass

    def _extract_findings(self, data, module):
        """Extrae hallazgos en formato normalizado."""
        finding_keys = [
            "findings", "vulnerabilities", "issues", "ioc_findings",
            "hardening_findings", "exposed_assets", "log_anomalies",
            "network_anomalies", "email_breaches"
        ]
        for key in finding_keys:
            items = data.get(key, [])
            for item in items:
                if isinstance(item, dict):
                    item["_source_module"] = module
                    item["_source_key"] = key
                    self.all_findings.append(item)

    def _severity_sort_key(self, f):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(f.get("severity", "info"), 5)

    # ──────────────────────────────────────────────────────────────────────────
    def generate(self, output_path=None):
        """Genera el informe PDF completo."""
        if not check_reportlab():
            return None

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm, mm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                         TableStyle, PageBreak, HRFlowable, KeepTogether)
        from reportlab.platypus import Drawing
        from reportlab.graphics.shapes import Rect, String, Circle, Line
        from reportlab.graphics.charts.piecharts import Pie
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        from reportlab.lib import colors

        # Output path
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            client_safe = self.client_name.replace(' ', '_').replace('/', '-')
            if self.session_dir:
                output_path = self.session_dir / f"INFORME_{client_safe}_{ts}.pdf"
            else:
                output_path = Path.home() / "Documents" / f"INFORME_{client_safe}_{ts}.pdf"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Convertir colores a reportlab
        def rc(t): return colors.Color(t[0], t[1], t[2])

        # Documento
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2.5*cm,
            title=f"Informe de Auditoría — {self.client_name}",
            author=self.company_name,
            subject="Informe de Seguridad Purple Team"
        )

        # Estilos
        styles = getSampleStyleSheet()
        style_title = ParagraphStyle('Title2', parent=styles['Normal'],
            fontSize=26, textColor=rc(self.WHITE), fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=6)
        style_subtitle = ParagraphStyle('Subtitle', parent=styles['Normal'],
            fontSize=13, textColor=rc(self.PURPLE_LIGHT), fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=4)
        style_h1 = ParagraphStyle('H1', parent=styles['Normal'],
            fontSize=16, textColor=rc(self.PURPLE_DARK), fontName='Helvetica-Bold',
            spaceBefore=14, spaceAfter=8, borderPad=4)
        style_h2 = ParagraphStyle('H2', parent=styles['Normal'],
            fontSize=12, textColor=rc(self.PURPLE), fontName='Helvetica-Bold',
            spaceBefore=10, spaceAfter=4)
        style_body = ParagraphStyle('Body', parent=styles['Normal'],
            fontSize=9.5, textColor=rc(self.DARK_TEXT), fontName='Helvetica',
            leading=14, alignment=TA_JUSTIFY, spaceAfter=4)
        style_small = ParagraphStyle('Small', parent=styles['Normal'],
            fontSize=8, textColor=rc(self.DARK_TEXT), fontName='Helvetica', leading=12)
        style_code = ParagraphStyle('Code', parent=styles['Normal'],
            fontSize=8, fontName='Courier', backColor=rc(self.GRAY_LIGHT),
            leftIndent=10, rightIndent=10, spaceBefore=4, spaceAfter=4)
        style_note = ParagraphStyle('Note', parent=styles['Normal'],
            fontSize=8.5, textColor=colors.HexColor('#555555'), fontName='Helvetica-Oblique',
            leftIndent=10, spaceAfter=4)

        story = []

        # ── PORTADA ───────────────────────────────────────────────────────────
        # Bloque de portada con fondo púrpura usando tabla
        cover_data = [[
            Paragraph(f"INFORME DE AUDITORÍA<br/>DE SEGURIDAD", style_title),
        ]]
        cover_table = Table(cover_data, colWidths=[17*cm])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), rc(self.PURPLE)),
            ('TOPPADDING', (0,0), (-1,-1), 30),
            ('BOTTOMPADDING', (0,0), (-1,-1), 30),
            ('LEFTPADDING', (0,0), (-1,-1), 20),
            ('RIGHTPADDING', (0,0), (-1,-1), 20),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), [6,6,6,6]),
        ]))
        story.append(cover_table)
        story.append(Spacer(1, 0.5*cm))

        # Info de portada
        ts_str = datetime.now().strftime("%d de %B de %Y")
        meta_data = [
            ["Cliente:", self.client_name],
            ["Preparado por:", self.company_name],
            ["Fecha:", ts_str],
            ["Clasificación:", "CONFIDENCIAL — USO INTERNO"],
            ["Tipo de informe:", self.report_type.upper()],
        ]
        meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('TEXTCOLOR', (0,0), (0,-1), rc(self.PURPLE)),
            ('TEXTCOLOR', (1,0), (1,-1), rc(self.DARK_TEXT)),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, rc(self.GRAY_MID)),
        ]))
        story.append(meta_table)

        # Aviso legal
        story.append(Spacer(1, 0.5*cm))
        legal_text = (
            "Este documento contiene información confidencial y está destinado exclusivamente "
            "al cliente indicado. Queda prohibida su reproducción, distribución o divulgación "
            "a terceros sin autorización expresa de {company}. "
            "La información aquí contenida ha sido obtenida en el contexto de una auditoría "
            "de seguridad autorizada.".format(company=self.company_name)
        )
        story.append(Paragraph(legal_text, style_note))
        story.append(PageBreak())

        # ── ÍNDICE ────────────────────────────────────────────────────────────
        story.append(Paragraph("ÍNDICE DE CONTENIDOS", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))
        toc_items = [
            ("1.", "Resumen Ejecutivo"),
            ("2.", "Metodología y Alcance"),
            ("3.", "Métricas de Riesgo"),
            ("4.", "Hallazgos por Módulo"),
            ("5.", "Análisis de Compliance"),
            ("6.", "Plan de Remediación Priorizado"),
            ("7.", "Conclusiones y Siguientes Pasos"),
        ]
        for num, title in toc_items:
            toc_row = [[Paragraph(num, style_small), Paragraph(title, style_small)]]
            toc_table = Table(toc_row, colWidths=[1*cm, 16*cm])
            toc_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (0,0), 'Helvetica-Bold'),
                ('TEXTCOLOR', (0,0), (0,0), rc(self.PURPLE)),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('TOPPADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(toc_table)
        story.append(PageBreak())

        # ── 1. RESUMEN EJECUTIVO ──────────────────────────────────────────────
        story.append(Paragraph("1. RESUMEN EJECUTIVO", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        # Contar hallazgos por severidad
        sev_counter = Counter(f.get("severity", "info") for f in self.all_findings)
        critical_n = sev_counter.get("critical", 0)
        high_n = sev_counter.get("high", 0)
        medium_n = sev_counter.get("medium", 0)
        low_n = sev_counter.get("low", 0)
        total_n = len(self.all_findings)

        # Determinar nivel de riesgo global
        if critical_n > 0:
            risk_level = "CRÍTICO"; risk_color = rc(self.RED_RISK)
        elif high_n > 2:
            risk_level = "ALTO"; risk_color = rc(self.ORANGE_RISK)
        elif high_n > 0 or medium_n > 3:
            risk_level = "MEDIO"; risk_color = rc(self.YELLOW_RISK)
        else:
            risk_level = "BAJO"; risk_color = rc(self.GREEN_OK)

        exec_text = (
            "Se ha realizado una auditoría de seguridad de tipo Purple Team para <b>{client}</b>, "
            "abarcando análisis de superficie de ataque externo, evaluación de controles defensivos, "
            "análisis de compliance normativo y pruebas de seguridad WiFi. "
            "La auditoría ha identificado un total de <b>{total} hallazgos</b>, "
            "con un nivel de riesgo global <b>{level}</b>."
        ).format(client=self.client_name, total=total_n, level=risk_level)
        story.append(Paragraph(exec_text, style_body))
        story.append(Spacer(1, 0.3*cm))

        # Tabla de métricas ejecutivas
        metrics_data = [
            ["Hallazgos Críticos", "Hallazgos Altos", "Hallazgos Medios", "Hallazgos Bajos"],
            [str(critical_n), str(high_n), str(medium_n), str(low_n)],
        ]
        metrics_table = Table(metrics_data, colWidths=[4.25*cm]*4)
        sev_bg_colors = [rc(self.RED_RISK), rc(self.ORANGE_RISK), rc(self.YELLOW_RISK), rc(self.GREEN_OK)]
        metrics_style = TableStyle([
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',    (0,1), (-1,1), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,0), 8.5),
            ('FONTSIZE',    (0,1), (-1,1), 22),
            ('ALIGN',       (0,0), (-1,-1), 'CENTER'),
            ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING',  (0,0), (-1,0), 8),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('TOPPADDING',  (0,1), (-1,1), 8),
            ('BOTTOMPADDING', (0,1), (-1,1), 12),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), [4,4,4,4]),
        ])
        for i, bg in enumerate(sev_bg_colors):
            metrics_style.add('BACKGROUND', (i,0), (i,-1), bg)
            metrics_style.add('TEXTCOLOR', (i,0), (i,-1), rc(self.WHITE))
        metrics_table.setStyle(metrics_style)
        story.append(metrics_table)
        story.append(Spacer(1, 0.5*cm))

        # Riesgo global badge
        risk_badge_data = [[Paragraph(f"NIVEL DE RIESGO GLOBAL: {risk_level}", ParagraphStyle(
            'RiskBadge', parent=styles['Normal'],
            fontSize=14, fontName='Helvetica-Bold',
            textColor=rc(self.WHITE), alignment=TA_CENTER))]]
        risk_table = Table(risk_badge_data, colWidths=[17*cm])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), risk_color),
            ('TOPPADDING', (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), [6,6,6,6]),
        ]))
        story.append(risk_table)
        story.append(PageBreak())

        # ── 2. METODOLOGÍA ────────────────────────────────────────────────────
        story.append(Paragraph("2. METODOLOGÍA Y ALCANCE", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        methodology_text = (
            "La auditoría se ha realizado siguiendo el framework <b>MITRE ATT&CK</b> para la "
            "fase ofensiva y los controles del <b>CIS Benchmark</b> y <b>NIST CSF</b> para la fase "
            "defensiva. El proceso sigue las 7 fases de la Metodología Purple Team:"
        )
        story.append(Paragraph(methodology_text, style_body))
        story.append(Spacer(1, 0.3*cm))

        phases = [
            ("Fase 1", "Reconocimiento Pasivo (OSINT)", "Recolección de inteligencia en fuentes abiertas sin contacto directo con el objetivo."),
            ("Fase 2", "Reconocimiento Activo", "Enumeración de servicios, puertos y tecnologías expuestas."),
            ("Fase 3", "Análisis de Vulnerabilidades", "Identificación de CVEs, configuraciones inseguras y debilidades de seguridad."),
            ("Fase 4", "Evaluación de Controles Defensivos", "Verificación de hardening, logs, detección de intrusiones y respuesta."),
            ("Fase 5", "Evaluación de Compliance", "Análisis de cumplimiento normativo (RGPD, ENS, PCI DSS)."),
            ("Fase 6", "Análisis WiFi", "Evaluación de la seguridad de la red inalámbrica y dispositivos conectados."),
            ("Fase 7", "Reporting y Remediación", "Generación de informe con hallazgos priorizados y plan de acción."),
        ]
        phases_data = [["Fase", "Nombre", "Descripción"]] + phases
        phases_table = Table(phases_data, colWidths=[1.8*cm, 4.5*cm, 10.7*cm])
        phases_style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), rc(self.PURPLE)),
            ('TEXTCOLOR', (0,0), (-1,0), rc(self.WHITE)),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,1), (0,-1), rc(self.PURPLE)),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [rc(self.WHITE), rc(self.GRAY_LIGHT)]),
            ('GRID', (0,0), (-1,-1), 0.5, rc(self.GRAY_MID)),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
        ])
        phases_table.setStyle(phases_style)
        story.append(phases_table)
        story.append(PageBreak())

        # ── 3. MÉTRICAS DE RIESGO ─────────────────────────────────────────────
        story.append(Paragraph("3. MÉTRICAS DE RIESGO", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        if self.all_findings:
            # Gráfico de barras por severidad
            from reportlab.graphics.shapes import Drawing
            from reportlab.graphics.charts.barcharts import VerticalBarChart
            from reportlab.graphics import renderPDF

            d = Drawing(400, 180)
            bc = VerticalBarChart()
            bc.x = 40; bc.y = 20; bc.height = 140; bc.width = 340
            sev_labels = ['Crítico', 'Alto', 'Medio', 'Bajo']
            sev_values = [critical_n, high_n, medium_n, low_n]
            bc.data = [sev_values]
            bc.categoryAxis.categoryNames = sev_labels
            bc.bars[0].fillColor = rc(self.PURPLE)
            bc.valueAxis.valueMin = 0
            bc.valueAxis.valueMax = max(sev_values) + 1 if sev_values else 5
            bc.valueAxis.valueStep = max(1, (max(sev_values) + 1) // 5) if sev_values else 1
            bc.groupSpacing = 10
            bc.barSpacing = 2
            # Colores por barra
            bc.bars[0].fillColor = rc(self.RED_RISK)
            bc.data = [[critical_n], [high_n], [medium_n], [low_n]]
            bc.bars[0].fillColor = rc(self.RED_RISK)
            bc.bars[1].fillColor = rc(self.ORANGE_RISK)
            bc.bars[2].fillColor = rc(self.YELLOW_RISK)
            bc.bars[3].fillColor = rc(self.GREEN_OK)
            bc.categoryAxis.categoryNames = ['Crítico', 'Alto', 'Medio', 'Bajo']
            bc.barWidth = 40
            bc.groupSpacing = 15
            d.add(bc)

            story.append(Paragraph("Distribución de Hallazgos por Severidad", style_h2))
            story.append(d)
            story.append(Spacer(1, 0.5*cm))

        # Tabla de módulos evaluados
        module_scores = []
        for module, data in self.data.items():
            score = data.get("defense_score") or data.get("hardening_score") or \
                    data.get("risk_score") or data.get("overall_compliance")
            if score is not None:
                module_scores.append((module.replace('_', ' ').title(), score))

        if module_scores:
            story.append(Paragraph("Puntuaciones por Módulo", style_h2))
            score_data = [["Módulo", "Puntuación", "Estado"]]
            for module, score in module_scores:
                if score >= 80: status = "✓ Bien"
                elif score >= 60: status = "~ Mejorable"
                else: status = "✗ Deficiente"
                score_data.append([module, f"{score}/100", status])

            score_table = Table(score_data, colWidths=[8*cm, 4*cm, 5*cm])
            score_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), rc(self.PURPLE)),
                ('TEXTCOLOR', (0,0), (-1,0), rc(self.WHITE)),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [rc(self.WHITE), rc(self.GRAY_LIGHT)]),
                ('GRID', (0,0), (-1,-1), 0.5, rc(self.GRAY_MID)),
                ('ALIGN', (1,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 7),
                ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
            ]))
            story.append(score_table)
        story.append(PageBreak())

        # ── 4. HALLAZGOS ─────────────────────────────────────────────────────
        story.append(Paragraph("4. HALLAZGOS POR SEVERIDAD", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        sorted_findings = sorted(self.all_findings, key=self._severity_sort_key)

        if not sorted_findings:
            story.append(Paragraph("No se encontraron hallazgos significativos en esta auditoría.", style_body))
        else:
            for i, finding in enumerate(sorted_findings[:50], 1):  # Max 50 findings
                sev = finding.get("severity", "info")
                sev_color = rc(self.SEVERITY_COLORS.get(sev, (0.5, 0.5, 0.5)))
                finding_type = finding.get("type", finding.get("check", "hallazgo")).replace('_', ' ').title()
                detail = finding.get("detail", finding.get("description", ""))
                remediation = finding.get("remediation", "")
                source = finding.get("_source_module", "")

                # Header del hallazgo
                finding_header = [[
                    Paragraph(f"{i:02d}. {finding_type}", ParagraphStyle(
                        'FH', parent=styles['Normal'],
                        fontSize=9.5, fontName='Helvetica-Bold', textColor=rc(self.WHITE))),
                    Paragraph(sev.upper(), ParagraphStyle(
                        'FS', parent=styles['Normal'],
                        fontSize=9, fontName='Helvetica-Bold', textColor=rc(self.WHITE),
                        alignment=TA_RIGHT)),
                ]]
                header_table = Table(finding_header, colWidths=[13*cm, 4*cm])
                header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), sev_color),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                    ('LEFTPADDING', (0,0), (0,-1), 10),
                    ('RIGHTPADDING', (-1,0), (-1,-1), 10),
                ]))

                # Detalle del hallazgo
                detail_rows = []
                if detail:
                    detail_rows.append([Paragraph("Descripción:", ParagraphStyle(
                        'DL', parent=styles['Normal'], fontSize=8.5, fontName='Helvetica-Bold',
                        textColor=rc(self.PURPLE))),
                        Paragraph(str(detail)[:300], style_small)])
                if remediation:
                    detail_rows.append([Paragraph("Remediación:", ParagraphStyle(
                        'RL', parent=styles['Normal'], fontSize=8.5, fontName='Helvetica-Bold',
                        textColor=rc(self.GREEN_OK))),
                        Paragraph(str(remediation)[:300], style_small)])
                if source:
                    detail_rows.append([Paragraph("Módulo:", ParagraphStyle(
                        'ML', parent=styles['Normal'], fontSize=8, fontName='Helvetica-Bold',
                        textColor=rc(self.GRAY_MID))),
                        Paragraph(source.title(), style_small)])

                if detail_rows:
                    detail_table = Table(detail_rows, colWidths=[2.5*cm, 14.5*cm])
                    detail_table.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), rc(self.GRAY_LIGHT)),
                        ('TOPPADDING', (0,0), (-1,-1), 5),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                        ('LEFTPADDING', (0,0), (-1,-1), 8),
                        ('RIGHTPADDING', (-1,0), (-1,-1), 8),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ]))
                    story.append(KeepTogether([header_table, detail_table, Spacer(1, 0.25*cm)]))
                else:
                    story.append(header_table)
                    story.append(Spacer(1, 0.25*cm))

        story.append(PageBreak())

        # ── 5. COMPLIANCE ─────────────────────────────────────────────────────
        story.append(Paragraph("5. ANÁLISIS DE COMPLIANCE NORMATIVO", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        compliance_data = self.data.get("compliance", {})
        if compliance_data:
            rgpd_score = compliance_data.get("rgpd", {}).get("score", 0)
            ens_score = compliance_data.get("ens", {}).get("score", 0)
            pci_score = compliance_data.get("pci_dss", {}).get("score", 0)
            overall = compliance_data.get("overall_compliance", 0)

            comp_table_data = [
                ["Normativa", "Score", "Estado", "Hallazgos"],
                ["RGPD / LOPD-GDD", f"{rgpd_score}%",
                 "Conforme" if rgpd_score>=80 else "Parcial" if rgpd_score>=60 else "No Conforme",
                 str(len(compliance_data.get("rgpd",{}).get("findings",[])))],
                ["ENS (Esquema Nacional)", f"{ens_score}%",
                 "Conforme" if ens_score>=80 else "Parcial" if ens_score>=60 else "No Conforme",
                 str(len(compliance_data.get("ens",{}).get("findings",[])))],
                ["PCI DSS", f"{pci_score}%",
                 "Conforme" if pci_score>=80 else "Parcial" if pci_score>=60 else "No Conforme",
                 str(len(compliance_data.get("pci_dss",{}).get("findings",[])))],
            ]
            comp_table = Table(comp_table_data, colWidths=[6*cm, 3*cm, 5*cm, 3*cm])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), rc(self.PURPLE)),
                ('TEXTCOLOR', (0,0), (-1,0), rc(self.WHITE)),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [rc(self.WHITE), rc(self.GRAY_LIGHT)]),
                ('GRID', (0,0), (-1,-1), 0.5, rc(self.GRAY_MID)),
                ('ALIGN', (1,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(comp_table)
        else:
            story.append(Paragraph(
                "No se han encontrado datos de compliance en esta sesión. "
                "Ejecute compliance/compliance_checker.py para obtener análisis normativo.",
                style_body))

        story.append(PageBreak())

        # ── 6. PLAN DE REMEDIACIÓN ────────────────────────────────────────────
        story.append(Paragraph("6. PLAN DE REMEDIACIÓN PRIORIZADO", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        story.append(Paragraph(
            "Los hallazgos se presentan ordenados por criticidad y facilidad de remediación. "
            "Se recomienda abordar los hallazgos críticos en un plazo máximo de 72 horas, "
            "los altos en 2 semanas y los medios en el siguiente ciclo de mejora.", style_body))
        story.append(Spacer(1, 0.3*cm))

        remediation_data = [["#", "Hallazgo", "Severidad", "Plazo", "Esfuerzo"]]
        timeframes = {"critical": "72h", "high": "2 semanas", "medium": "1 mes", "low": "3 meses"}
        efforts = {"critical": "Alto", "high": "Medio-Alto", "medium": "Medio", "low": "Bajo"}

        for i, f in enumerate(sorted_findings[:20], 1):
            sev = f.get("severity", "info")
            name = f.get("type", f.get("check", "hallazgo")).replace('_', ' ').title()[:45]
            remediation_data.append([
                str(i), name, sev.upper(),
                timeframes.get(sev, "3 meses"),
                efforts.get(sev, "Variable")
            ])

        if len(remediation_data) > 1:
            rem_table = Table(remediation_data, colWidths=[0.8*cm, 8.5*cm, 2.5*cm, 2.5*cm, 2.7*cm])
            rem_style = TableStyle([
                ('BACKGROUND', (0,0), (-1,0), rc(self.PURPLE)),
                ('TEXTCOLOR', (0,0), (-1,0), rc(self.WHITE)),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [rc(self.WHITE), rc(self.GRAY_LIGHT)]),
                ('GRID', (0,0), (-1,-1), 0.5, rc(self.GRAY_MID)),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('ALIGN', (0,0), (0,-1), 'CENTER'),
                ('ALIGN', (2,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
            ])
            # Colorear severidades
            for row_idx, row_data in enumerate(remediation_data[1:], 1):
                sev = row_data[2].lower()
                sev_c = self.SEVERITY_COLORS.get(sev, (0.5, 0.5, 0.5))
                rem_style.add('TEXTCOLOR', (2, row_idx), (2, row_idx), rc(sev_c))
                rem_style.add('FONTNAME', (2, row_idx), (2, row_idx), 'Helvetica-Bold')
            rem_table.setStyle(rem_style)
            story.append(rem_table)

        story.append(PageBreak())

        # ── 7. CONCLUSIONES ───────────────────────────────────────────────────
        story.append(Paragraph("7. CONCLUSIONES Y SIGUIENTES PASOS", style_h1))
        story.append(HRFlowable(width="100%", thickness=2, color=rc(self.PURPLE), spaceAfter=8))

        conclusion_text = (
            "Tras el análisis realizado, se concluye que <b>{client}</b> presenta un nivel de "
            "riesgo <b>{level}</b> con <b>{total} hallazgos identificados</b> ({crit} críticos, "
            "{high} altos, {med} medios, {low} bajos). "
            "Se recomienda abordar de forma inmediata los hallazgos críticos y establecer un "
            "programa de mejora continua de seguridad que incluya revisiones periódicas "
            "y formación al personal."
        ).format(
            client=self.client_name, level=risk_level, total=total_n,
            crit=critical_n, high=high_n, med=medium_n, low=low_n
        )
        story.append(Paragraph(conclusion_text, style_body))
        story.append(Spacer(1, 0.5*cm))

        next_steps = [
            ["Inmediato\n(0-72h)", "Remediar hallazgos críticos identificados en este informe"],
            ["Corto plazo\n(2 semanas)", "Implementar controles de seguridad para hallazgos altos"],
            ["Medio plazo\n(1 mes)", "Resolver hallazgos medios y configurar monitoreo continuo"],
            ["Largo plazo\n(3 meses)", "Auditoría de seguimiento para verificar remediaciones"],
            ["Continuo", "Programa de formación en ciberseguridad para el personal"],
        ]
        ns_data = [["Plazo", "Acción"]] + next_steps
        ns_table = Table(ns_data, colWidths=[3.5*cm, 13.5*cm])
        ns_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), rc(self.PURPLE)),
            ('TEXTCOLOR', (0,0), (-1,0), rc(self.WHITE)),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,1), (0,-1), rc(self.PURPLE)),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [rc(self.WHITE), rc(self.GRAY_LIGHT)]),
            ('GRID', (0,0), (-1,-1), 0.5, rc(self.GRAY_MID)),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(ns_table)
        story.append(Spacer(1, 1*cm))

        # Footer final
        footer_data = [[Paragraph(
            f"{self.company_name} · Informe confidencial · {ts_str}",
            ParagraphStyle('Footer', parent=styles['Normal'],
                fontSize=8, textColor=rc(self.WHITE), alignment=TA_CENTER))]]
        footer_table = Table(footer_data, colWidths=[17*cm])
        footer_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), rc(self.PURPLE)),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(footer_table)

        # Construir PDF
        info("Generando PDF profesional...")
        doc.build(story)
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
