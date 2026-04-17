# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║       PURPLE TEAM SUITE - GENERADOR DE INFORMES PDF          ║
║       Informe profesional de auditoría de seguridad          ║
║                                                              ║
║  Uso:                                                        ║
║    python report_generator.py                                ║
║      → modo interactivo (pide datos del cliente)             ║
║                                                              ║
║    python report_generator.py --session <ruta_sesion>        ║
║      → genera informe desde datos del orquestador            ║
║                                                              ║
║    python report_generator.py --demo                         ║
║      → genera informe de demostración con datos ficticios    ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, Image
)
from reportlab.lib.colors import HexColor
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics import renderPDF


# ─── Paleta corporativa ───────────────────────────────────────────────────────
PURPLE_DARK  = HexColor('#3B0764')
PURPLE_MID   = HexColor('#7E22CE')
PURPLE_LIGHT = HexColor('#A855F7')
PURPLE_BG    = HexColor('#F5F3FF')
RED_CRIT     = HexColor('#DC2626')
RED_BG       = HexColor('#FEF2F2')
ORANGE_HIGH  = HexColor('#EA580C')
ORANGE_BG    = HexColor('#FFF7ED')
YELLOW_MED   = HexColor('#D97706')
YELLOW_BG    = HexColor('#FFFBEB')
GREEN_LOW    = HexColor('#16A34A')
GREEN_BG     = HexColor('#F0FDF4')
BLUE_INFO    = HexColor('#2563EB')
BLUE_BG      = HexColor('#EFF6FF')
GRAY_DARK    = HexColor('#111827')
GRAY_MID     = HexColor('#6B7280')
GRAY_LIGHT   = HexColor('#F9FAFB')
GRAY_BORDER  = HexColor('#E5E7EB')
WHITE        = colors.white

W, H = A4  # 595.27 x 841.89 pts
MARGIN_L = 2.2 * cm
MARGIN_R = 2.2 * cm
MARGIN_T = 1.4 * cm
MARGIN_B = 1.4 * cm
CONTENT_W = W - MARGIN_L - MARGIN_R


# ─── Estilos ──────────────────────────────────────────────────────────────────
def make_styles():
    s = getSampleStyleSheet()
    add = s.add

    add(ParagraphStyle('PT_Title',       fontName='Helvetica-Bold',   fontSize=30, textColor=WHITE,       alignment=TA_LEFT,    leading=36, spaceAfter=6))
    add(ParagraphStyle('PT_Subtitle',    fontName='Helvetica',        fontSize=13, textColor=HexColor('#DDD6FE'), alignment=TA_LEFT, leading=18, spaceAfter=4))
    add(ParagraphStyle('PT_CoverMeta',   fontName='Helvetica',        fontSize=9,  textColor=HexColor('#C4B5FD'), alignment=TA_LEFT, spaceAfter=3))
    add(ParagraphStyle('PT_H1',          fontName='Helvetica-Bold',   fontSize=15, textColor=PURPLE_DARK,  spaceBefore=18, spaceAfter=6,  leading=20))
    add(ParagraphStyle('PT_H2',          fontName='Helvetica-Bold',   fontSize=11, textColor=PURPLE_MID,   spaceBefore=10, spaceAfter=4,  leading=15))
    add(ParagraphStyle('PT_Body',        fontName='Helvetica',        fontSize=9.5,textColor=GRAY_DARK,    spaceAfter=5,  leading=15, alignment=TA_JUSTIFY))
    add(ParagraphStyle('PT_BodyLeft',    fontName='Helvetica',        fontSize=9.5,textColor=GRAY_DARK,    spaceAfter=5,  leading=15))
    add(ParagraphStyle('PT_Small',       fontName='Helvetica',        fontSize=8,  textColor=GRAY_MID,     spaceAfter=3,  leading=12))
    add(ParagraphStyle('PT_Code',        fontName='Courier',          fontSize=8,  textColor=HexColor('#1E293B'), backColor=HexColor('#F1F5F9'), spaceAfter=6, leading=12, leftIndent=8, rightIndent=8))
    add(ParagraphStyle('PT_TableHdr',    fontName='Helvetica-Bold',   fontSize=8.5,textColor=WHITE,        alignment=TA_CENTER))
    add(ParagraphStyle('PT_TableCell',   fontName='Helvetica',        fontSize=8.5,textColor=GRAY_DARK,    alignment=TA_LEFT,  leading=13))
    add(ParagraphStyle('PT_TableCellC',  fontName='Helvetica',        fontSize=8.5,textColor=GRAY_DARK,    alignment=TA_CENTER,leading=13))
    add(ParagraphStyle('PT_FooterTxt',   fontName='Helvetica',        fontSize=7.5,textColor=GRAY_MID,     alignment=TA_CENTER))
    add(ParagraphStyle('PT_Bullet',      fontName='Helvetica',        fontSize=9.5,textColor=GRAY_DARK,    spaceAfter=3,  leading=14, leftIndent=10))
    add(ParagraphStyle('PT_FindingTitle',fontName='Helvetica-Bold',   fontSize=10, textColor=GRAY_DARK,    spaceAfter=3,  leading=14))
    add(ParagraphStyle('PT_Label',       fontName='Helvetica-Bold',   fontSize=8,  textColor=GRAY_MID,     spaceAfter=1))
    add(ParagraphStyle('PT_Value',       fontName='Helvetica',        fontSize=9,  textColor=GRAY_DARK,    spaceAfter=6,  leading=13))
    return s


# ─── Severidad helpers ────────────────────────────────────────────────────────
SEV_CFG = {
    "CRITICO":  {"color": RED_CRIT,    "bg": RED_BG,    "label": "CRÍTICO",  "cvss": "9.0-10.0", "sla": "24 horas"},
    "ALTO":     {"color": ORANGE_HIGH, "bg": ORANGE_BG, "label": "ALTO",     "cvss": "7.0-8.9",  "sla": "7 días"},
    "MEDIO":    {"color": YELLOW_MED,  "bg": YELLOW_BG, "label": "MEDIO",    "cvss": "4.0-6.9",  "sla": "30 días"},
    "BAJO":     {"color": GREEN_LOW,   "bg": GREEN_BG,  "label": "BAJO",     "cvss": "0.1-3.9",  "sla": "90 días"},
    "INFO":     {"color": BLUE_INFO,   "bg": BLUE_BG,   "label": "INFO",     "cvss": "0.0",      "sla": "Revisión"},
}

def sev_badge(sev_key, styles):
    cfg = SEV_CFG.get(sev_key.upper(), SEV_CFG["INFO"])
    data = [[Paragraph(f"<b>{cfg['label']}</b>", ParagraphStyle(
        'badge', fontName='Helvetica-Bold', fontSize=8,
        textColor=WHITE, alignment=TA_CENTER))]]
    t = Table(data, colWidths=[2*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), cfg['color']),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [3,3,3,3]),
    ]))
    return t


# ─── Header / Footer ─────────────────────────────────────────────────────────
def make_header_footer(audit_info):
    def _draw(canvas, doc):
        canvas.saveState()

        # Header bar
        canvas.setFillColor(PURPLE_DARK)
        canvas.rect(0, H - 1.1*cm, W, 1.1*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 7.5)
        canvas.drawString(MARGIN_L, H - 0.65*cm, f"INFORME DE AUDITORÍA DE SEGURIDAD  ·  {audit_info['client'].upper()}")
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(HexColor('#C4B5FD'))
        canvas.drawRightString(W - MARGIN_R, H - 0.65*cm, f"REF: {audit_info['ref']}  ·  CONFIDENCIAL")

        # Footer bar
        canvas.setFillColor(GRAY_LIGHT)
        canvas.rect(0, 0, W, 0.95*cm, fill=1, stroke=0)
        canvas.setFillColor(GRAY_MID)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(MARGIN_L, 0.35*cm, f"Purple Team Security  ·  {audit_info['auditor']}")
        canvas.drawCentredString(W/2, 0.35*cm, f"Página {doc.page}")
        canvas.drawRightString(W - MARGIN_R, 0.35*cm, audit_info['date'])

        # Separador línea
        canvas.setStrokeColor(GRAY_BORDER)
        canvas.setLineWidth(0.3)
        canvas.line(MARGIN_L, 0.95*cm, W - MARGIN_R, 0.95*cm)

        canvas.restoreState()
    return _draw


# ─── PORTADA ──────────────────────────────────────────────────────────────────
def cover_page(audit_info, styles):
    elems = []

    # Bloque de color principal
    cover_top = Table([['']], colWidths=[CONTENT_W], rowHeights=[7.5*cm])
    cover_top.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PURPLE_DARK),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    elems.append(cover_top)

    # Textos sobre el bloque (como tabla encima del espacio)
    inner_data = [
        [Paragraph("INFORME DE AUDITORÍA", ParagraphStyle('cv1', fontName='Helvetica', fontSize=11, textColor=PURPLE_LIGHT, alignment=TA_LEFT))],
        [Paragraph("DE SEGURIDAD", ParagraphStyle('cv2', fontName='Helvetica-Bold', fontSize=30, textColor=WHITE, alignment=TA_LEFT, leading=34))],
        [Spacer(1, 0.3*cm)],
        [Paragraph(audit_info['client'], ParagraphStyle('cv3', fontName='Helvetica-Bold', fontSize=16, textColor=HexColor('#DDD6FE'), alignment=TA_LEFT))],
        [Paragraph(audit_info['scope_short'], ParagraphStyle('cv4', fontName='Helvetica', fontSize=11, textColor=HexColor('#C4B5FD'), alignment=TA_LEFT))],
    ]
    inner_table = Table(inner_data, colWidths=[CONTENT_W])
    inner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PURPLE_DARK),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (0,0), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))

    # Pegamos los textos sobre el bloque oscuro combinándolos
    elems = []  # reset
    block_data = [
        [Paragraph("INFORME DE AUDITORÍA DE SEGURIDAD", ParagraphStyle(
            'cv_tag', fontName='Helvetica', fontSize=10, textColor=PURPLE_LIGHT, alignment=TA_LEFT))],
        [Spacer(1, 0.2*cm)],
        [Paragraph(audit_info['client'], ParagraphStyle(
            'cv_client', fontName='Helvetica-Bold', fontSize=26, textColor=WHITE, alignment=TA_LEFT, leading=30))],
        [Paragraph(audit_info['scope_short'], ParagraphStyle(
            'cv_scope', fontName='Helvetica', fontSize=12, textColor=HexColor('#C4B5FD'), alignment=TA_LEFT))],
        [Spacer(1, 0.8*cm)],
    ]
    block_table = Table(block_data, colWidths=[CONTENT_W])
    block_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), PURPLE_DARK),
        ('TOPPADDING', (0,0), (0,0), 40),
        ('BOTTOMPADDING', (0,-1), (0,-1), 20),
        ('LEFTPADDING', (0,0), (-1,-1), 16),
        ('RIGHTPADDING', (0,0), (-1,-1), 16),
        ('TOPPADDING', (0,1), (0,-1), 4),
        ('BOTTOMPADDING', (0,0), (0,-2), 4),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [8,8,0,0]),
    ]))
    elems.append(block_table)

    # Métricas resumen en tarjetas
    sev = audit_info.get('severity_count', {})
    risk = audit_info.get('risk_score', 0)
    risk_color = RED_CRIT if risk >= 7 else (ORANGE_HIGH if risk >= 4 else GREEN_LOW)

    cards_data = [[
        Paragraph(f"<b>{sev.get('CRITICO',0)}</b>", ParagraphStyle('c1', fontName='Helvetica-Bold', fontSize=22, textColor=RED_CRIT, alignment=TA_CENTER)),
        Paragraph(f"<b>{sev.get('ALTO',0)}</b>",    ParagraphStyle('c2', fontName='Helvetica-Bold', fontSize=22, textColor=ORANGE_HIGH, alignment=TA_CENTER)),
        Paragraph(f"<b>{sev.get('MEDIO',0)}</b>",   ParagraphStyle('c3', fontName='Helvetica-Bold', fontSize=22, textColor=YELLOW_MED, alignment=TA_CENTER)),
        Paragraph(f"<b>{sev.get('BAJO',0)}</b>",    ParagraphStyle('c4', fontName='Helvetica-Bold', fontSize=22, textColor=GREEN_LOW, alignment=TA_CENTER)),
        Paragraph(f"<b>{risk:.1f}</b>",              ParagraphStyle('c5', fontName='Helvetica-Bold', fontSize=22, textColor=risk_color, alignment=TA_CENTER)),
    ],[
        Paragraph("CRÍTICOS",   ParagraphStyle('l1', fontName='Helvetica', fontSize=7.5, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("ALTOS",      ParagraphStyle('l2', fontName='Helvetica', fontSize=7.5, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("MEDIOS",     ParagraphStyle('l3', fontName='Helvetica', fontSize=7.5, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("BAJOS",      ParagraphStyle('l4', fontName='Helvetica', fontSize=7.5, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("RIESGO/10",  ParagraphStyle('l5', fontName='Helvetica', fontSize=7.5, textColor=GRAY_MID, alignment=TA_CENTER)),
    ]]
    cw = CONTENT_W / 5
    cards_table = Table(cards_data, colWidths=[cw]*5)
    cards_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), WHITE),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, GRAY_BORDER),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [0,0,6,6]),
        ('LINEABOVE', (0,0), (-1,0), 3, PURPLE_MID),
    ]))
    elems.append(cards_table)
    elems.append(Spacer(1, 0.5*cm))

    # Metadatos del informe
    meta = [
        ["Cliente",      audit_info['client'],
         "Fecha inicio", audit_info['start_date']],
        ["Auditor",      audit_info['auditor'],
         "Fecha fin",    audit_info['end_date']],
        ["Referencia",   audit_info['ref'],
         "Clasificación","CONFIDENCIAL"],
        ["Tipo auditoría",audit_info['audit_type'],
         "Versión",      audit_info['version']],
    ]
    meta_rows = []
    for row in meta:
        meta_rows.append([
            Paragraph(f"<b>{row[0]}</b>", ParagraphStyle('mk', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY_MID)),
            Paragraph(row[1], ParagraphStyle('mv', fontName='Helvetica', fontSize=9, textColor=GRAY_DARK)),
            Paragraph(f"<b>{row[2]}</b>", ParagraphStyle('mk2', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY_MID)),
            Paragraph(row[3], ParagraphStyle('mv2', fontName='Helvetica', fontSize=9, textColor=GRAY_DARK)),
        ])

    meta_table = Table(meta_rows, colWidths=[3.2*cm, 5.3*cm, 3.2*cm, 5.3*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), GRAY_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
        ('BACKGROUND', (0,0), (0,-1), HexColor('#EDE9FE')),
        ('BACKGROUND', (2,0), (2,-1), HexColor('#EDE9FE')),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [4,4,4,4]),
    ]))
    elems.append(meta_table)
    elems.append(Spacer(1, 0.5*cm))

    # Advertencia legal
    legal_data = [[Paragraph(
        "<b>DOCUMENTO CONFIDENCIAL</b> — Este informe contiene información sensible sobre "
        "vulnerabilidades de seguridad. Su distribución está restringida exclusivamente al "
        "personal autorizado del cliente. Queda prohibida su reproducción o divulgación sin "
        "autorización expresa por escrito de Purple Team Security.",
        ParagraphStyle('legal', fontName='Helvetica', fontSize=8, textColor=HexColor('#92400E'),
                       leading=12, alignment=TA_JUSTIFY)
    )]]
    legal_table = Table(legal_data, colWidths=[CONTENT_W])
    legal_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), HexColor('#FFFBEB')),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LINEBEFORE', (0,0), (0,-1), 3, HexColor('#D97706')),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [0,4,4,0]),
    ]))
    elems.append(legal_table)
    elems.append(PageBreak())
    return elems


# ─── RESUMEN EJECUTIVO ────────────────────────────────────────────────────────
def exec_summary(audit_info, styles):
    elems = []

    # Header de sección
    def sec_hdr(title):
        bar_data = [[Paragraph(title, styles['PT_H1'])]]
        t = Table(bar_data, colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,-1), 2, PURPLE_MID),
        ]))
        return t

    elems.append(sec_hdr("1. RESUMEN EJECUTIVO"))
    elems.append(Spacer(1, 0.2*cm))

    # Texto ejecutivo
    risk = audit_info.get('risk_score', 0)
    risk_label = "ALTO" if risk >= 7 else ("MEDIO" if risk >= 4 else "BAJO")
    sev = audit_info.get('severity_count', {})
    total = sum(sev.values())

    exec_text = (
        f"En el período comprendido entre <b>{audit_info['start_date']}</b> y "
        f"<b>{audit_info['end_date']}</b>, el equipo de Purple Team Security llevó a cabo "
        f"una auditoría de seguridad de tipo <b>{audit_info['audit_type']}</b> sobre los "
        f"sistemas de <b>{audit_info['client']}</b>, con alcance: <i>{audit_info['scope_full']}</i>."
    )
    elems.append(Paragraph(exec_text, styles['PT_Body']))
    elems.append(Spacer(1, 0.15*cm))

    result_text = (
        f"Como resultado del proceso, se identificaron un total de <b>{total} hallazgos de seguridad</b>, "
        f"de los cuales <b>{sev.get('CRITICO',0)} son de severidad Crítica</b>, "
        f"{sev.get('ALTO',0)} de severidad Alta, {sev.get('MEDIO',0)} de severidad Media "
        f"y {sev.get('BAJO',0)} de severidad Baja. "
        f"El nivel de riesgo global de la organización se evalúa como <b>{risk_label}</b> "
        f"con una puntuación de <b>{risk:.1f}/10</b>."
    )
    elems.append(Paragraph(result_text, styles['PT_Body']))
    elems.append(Spacer(1, 0.3*cm))

    # Tabla de hallazgos por área
    modules = audit_info.get('modules_summary', [])
    if modules:
        elems.append(Paragraph("Distribución de hallazgos por área auditada:", styles['PT_H2']))
        area_data = [["ÁREA", "MÓDULO", "HALLAZGOS", "SEVERIDAD MÁX.", "ESTADO"]]
        for m in modules:
            area_data.append([
                Paragraph(m.get('area',''), styles['PT_TableCell']),
                Paragraph(m.get('module',''), styles['PT_TableCell']),
                Paragraph(str(m.get('count',0)), styles['PT_TableCellC']),
                Paragraph(m.get('max_sev','INFO'), styles['PT_TableCellC']),
                Paragraph(m.get('status','Completado'), styles['PT_TableCellC']),
            ])
        area_table = Table(area_data, colWidths=[3.5*cm, 4*cm, 2.5*cm, 3*cm, 3*cm])
        area_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), PURPLE_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GRAY_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
            ('ALIGN', (0,1), (0,-1), 'LEFT'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'),
        ]))
        elems.append(area_table)
        elems.append(Spacer(1, 0.3*cm))

    # Recomendaciones ejecutivas top 3
    recs = audit_info.get('top_recommendations', [])
    if recs:
        elems.append(Paragraph("Acciones prioritarias recomendadas:", styles['PT_H2']))
        for i, rec in enumerate(recs[:5], 1):
            elems.append(Paragraph(
                f"<b>{i}.</b>  {rec}",
                ParagraphStyle('rec', fontName='Helvetica', fontSize=9.5,
                               textColor=GRAY_DARK, leading=15, spaceAfter=5, leftIndent=6)
            ))

    elems.append(PageBreak())
    return elems


# ─── HALLAZGOS DETALLADOS ─────────────────────────────────────────────────────
def findings_section(findings, styles):
    elems = []

    def sec_hdr(title):
        bar_data = [[Paragraph(title, styles['PT_H1'])]]
        t = Table(bar_data, colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,-1), 2, PURPLE_MID),
        ]))
        return t

    elems.append(sec_hdr("2. HALLAZGOS DETALLADOS"))
    elems.append(Spacer(1, 0.2*cm))

    if not findings:
        elems.append(Paragraph("No se identificaron hallazgos significativos.", styles['PT_Body']))
        elems.append(PageBreak())
        return elems

    for idx, f in enumerate(findings, 1):
        sev_key = f.get('severity', 'INFO').upper()
        cfg = SEV_CFG.get(sev_key, SEV_CFG['INFO'])

        block = []

        # Cabecera del hallazgo
        hdr_data = [[
            Paragraph(f"<b>F-{idx:02d}</b>", ParagraphStyle(
                'fid', fontName='Helvetica-Bold', fontSize=9,
                textColor=cfg['color'], alignment=TA_CENTER)),
            Paragraph(f"<b>{f.get('title','Sin título')}</b>", ParagraphStyle(
                'ftitle', fontName='Helvetica-Bold', fontSize=10.5,
                textColor=GRAY_DARK, alignment=TA_LEFT)),
            Paragraph(f"<b>{cfg['label']}</b>", ParagraphStyle(
                'fsev', fontName='Helvetica-Bold', fontSize=9,
                textColor=WHITE, alignment=TA_CENTER)),
        ]]
        hdr_table = Table(hdr_data, colWidths=[1.5*cm, CONTENT_W - 4*cm, 2.3*cm])
        hdr_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), cfg['bg']),
            ('BACKGROUND', (2,0), (2,0), cfg['color']),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBEFORE', (0,0), (0,-1), 4, cfg['color']),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), [4,4,0,0]),
        ]))
        block.append(hdr_table)

        # Metadatos del hallazgo
        meta_items = [
            ("CVSS Score", f.get('cvss', cfg['cvss'])),
            ("MITRE ATT&CK", f.get('mitre', 'N/A')),
            ("Área afectada", f.get('area', 'N/A')),
            ("SLA remediación", cfg['sla']),
        ]
        meta_data = [[
            Paragraph(f"<b>{k}</b>", styles['PT_Label']),
            Paragraph(v, styles['PT_Value']),
        ] for k, v in meta_items]

        meta_pairs = []
        for i in range(0, len(meta_data), 2):
            row = meta_data[i][:]
            if i + 1 < len(meta_data):
                row += meta_data[i+1]
            else:
                row += [Paragraph('', styles['PT_Label']), Paragraph('', styles['PT_Value'])]
            meta_pairs.append(row)

        meta_table = Table(meta_pairs, colWidths=[3*cm, 4.5*cm, 3*cm, 5.5*cm])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), WHITE),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
        ]))
        block.append(meta_table)

        # Descripción, impacto, evidencia, remediación
        def field_block(label, content, bg=WHITE):
            rows = [
                [Paragraph(f"<b>{label}</b>", styles['PT_Label'])],
                [Paragraph(content, styles['PT_BodyLeft'])],
            ]
            t = Table(rows, colWidths=[CONTENT_W])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), bg),
                ('TOPPADDING', (0,0), (0,0), 6),
                ('BOTTOMPADDING', (0,0), (0,0), 2),
                ('TOPPADDING', (0,1), (0,1), 2),
                ('BOTTOMPADDING', (0,1), (0,1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,1), (0,1), 0.3, GRAY_BORDER),
            ]))
            return t

        block.append(field_block("DESCRIPCIÓN", f.get('description', 'Sin descripción.')))
        block.append(field_block("IMPACTO", f.get('impact', 'No especificado.'), HexColor('#FAFAFA')))

        if f.get('evidence'):
            ev_rows = [
                [Paragraph("<b>EVIDENCIA</b>", styles['PT_Label'])],
                [Paragraph(f.get('evidence',''), styles['PT_Code'])],
            ]
            ev_t = Table(ev_rows, colWidths=[CONTENT_W])
            ev_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), WHITE),
                ('BACKGROUND', (0,1), (0,1), HexColor('#F8FAFC')),
                ('TOPPADDING', (0,0), (0,0), 6),
                ('BOTTOMPADDING', (0,0), (0,0), 2),
                ('TOPPADDING', (0,1), (0,1), 4),
                ('BOTTOMPADDING', (0,1), (0,1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,1), (0,1), 0.3, GRAY_BORDER),
            ]))
            block.append(ev_t)

        block.append(field_block("RECOMENDACIÓN", f.get('recommendation', 'Consultar con el equipo de seguridad.'), HexColor('#F0FDF4')))

        # Cerrar bloque con borde inferior redondeado
        close_data = [['']]
        close_t = Table(close_data, colWidths=[CONTENT_W], rowHeights=[0.15*cm])
        close_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), GRAY_BORDER),
            ('ROUNDEDCORNERS', (0,0), (-1,-1), [0,0,4,4]),
        ]))
        block.append(close_t)
        block.append(Spacer(1, 0.4*cm))

        elems.append(KeepTogether(block[:4]))  # Mantener cabecera + meta juntos
        for item in block[4:]:
            elems.append(item)

    elems.append(PageBreak())
    return elems


# ─── MITRE ATT&CK MAPPING ─────────────────────────────────────────────────────
def mitre_section(audit_info, styles):
    elems = []

    def sec_hdr(title):
        bar_data = [[Paragraph(title, styles['PT_H1'])]]
        t = Table(bar_data, colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,-1), 2, PURPLE_MID),
        ]))
        return t

    elems.append(sec_hdr("3. MAPEO MITRE ATT&CK"))
    elems.append(Spacer(1, 0.15*cm))
    elems.append(Paragraph(
        "Las técnicas identificadas durante la auditoría se mapean al framework MITRE ATT&CK "
        "para facilitar la comprensión del vector de ataque y la priorización de controles defensivos:",
        styles['PT_Body']
    ))
    elems.append(Spacer(1, 0.2*cm))

    mitre = audit_info.get('mitre_techniques', [])
    if mitre:
        mitre_data = [["ID TÉCNICA", "NOMBRE", "TÁCTICA", "HALLAZGO REF.", "ESTADO"]]
        seen = set()
        for t in mitre:
            key = t.get('id','')
            if key in seen:
                continue
            seen.add(key)
            mitre_data.append([
                Paragraph(f"<b>{t.get('id','')}</b>", ParagraphStyle(
                    'mit_id', fontName='Helvetica-Bold', fontSize=8.5,
                    textColor=PURPLE_MID, alignment=TA_CENTER)),
                Paragraph(t.get('name',''), styles['PT_TableCell']),
                Paragraph(t.get('tactic','Reconocimiento'), styles['PT_TableCellC']),
                Paragraph(t.get('ref','F-01'), styles['PT_TableCellC']),
                Paragraph("Detectado", ParagraphStyle(
                    'mit_st', fontName='Helvetica-Bold', fontSize=8,
                    textColor=RED_CRIT, alignment=TA_CENTER)),
            ])

        mitre_table = Table(mitre_data, colWidths=[2.8*cm, 5.5*cm, 3*cm, 2.5*cm, 2.2*cm])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), PURPLE_DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('ALIGN', (1,1), (1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GRAY_LIGHT]),
            ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
        ]))
        elems.append(mitre_table)

    elems.append(PageBreak())
    return elems


# ─── PLAN DE REMEDIACIÓN ──────────────────────────────────────────────────────
def remediation_section(findings, audit_info, styles):
    elems = []

    def sec_hdr(title):
        bar_data = [[Paragraph(title, styles['PT_H1'])]]
        t = Table(bar_data, colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,-1), 2, PURPLE_MID),
        ]))
        return t

    elems.append(sec_hdr("4. PLAN DE REMEDIACIÓN"))
    elems.append(Spacer(1, 0.15*cm))
    elems.append(Paragraph(
        "A continuación se presenta el plan de remediación priorizado por severidad. "
        "Se recomienda abordar los hallazgos críticos y altos en primer lugar, "
        "siguiendo los plazos indicados en la columna SLA:",
        styles['PT_Body']
    ))
    elems.append(Spacer(1, 0.2*cm))

    rem_data = [["REF.", "HALLAZGO", "SEVERIDAD", "SLA", "RESPONSABLE", "ESTADO"]]
    for idx, f in enumerate(sorted(findings, key=lambda x: ['CRITICO','ALTO','MEDIO','BAJO','INFO'].index(x.get('severity','INFO').upper())), 1):
        sev_key = f.get('severity','INFO').upper()
        cfg = SEV_CFG.get(sev_key, SEV_CFG['INFO'])
        rem_data.append([
            Paragraph(f"F-{idx:02d}", styles['PT_TableCellC']),
            Paragraph(f.get('title','')[:50] + ('...' if len(f.get('title','')) > 50 else ''), styles['PT_TableCell']),
            Paragraph(f"<b>{cfg['label']}</b>", ParagraphStyle(
                'rsev', fontName='Helvetica-Bold', fontSize=8,
                textColor=cfg['color'], alignment=TA_CENTER)),
            Paragraph(cfg['sla'], styles['PT_TableCellC']),
            Paragraph(f.get('owner', audit_info.get('client_contact','TI/Seguridad')), styles['PT_TableCellC']),
            Paragraph("Pendiente", ParagraphStyle(
                'rst', fontName='Helvetica', fontSize=8,
                textColor=ORANGE_HIGH, alignment=TA_CENTER)),
        ])

    rem_table = Table(rem_data, colWidths=[1.5*cm, 5.5*cm, 2.2*cm, 2.5*cm, 2.8*cm, 2.5*cm])
    rem_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PURPLE_DARK),
        ('TEXTCOLOR', (0,0), (-1,0), WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('ALIGN', (1,1), (1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GRAY_LIGHT]),
        ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
    ]))
    elems.append(rem_table)
    elems.append(PageBreak())
    return elems


# ─── FIRMAS Y CIERRE ──────────────────────────────────────────────────────────
def closing_section(audit_info, styles):
    elems = []

    def sec_hdr(title):
        bar_data = [[Paragraph(title, styles['PT_H1'])]]
        t = Table(bar_data, colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0,0), (-1,-1), 2, PURPLE_MID),
        ]))
        return t

    elems.append(sec_hdr("5. CONCLUSIONES Y FIRMA"))
    elems.append(Spacer(1, 0.2*cm))

    conclusion = (
        f"La auditoría de seguridad realizada sobre los sistemas de <b>{audit_info['client']}</b> "
        f"ha permitido identificar un total de <b>{sum(audit_info.get('severity_count',{}).values())} "
        f"hallazgos</b> que requieren atención por parte del equipo técnico. "
        f"Se recomienda establecer un plan de remediación siguiendo los plazos indicados "
        f"y realizar una auditoría de seguimiento (retest) una vez aplicadas las correcciones "
        f"para verificar la efectividad de las medidas implementadas."
    )
    elems.append(Paragraph(conclusion, styles['PT_Body']))
    elems.append(Spacer(1, 0.5*cm))

    # Bloques de firma
    firma_data = [[
        Paragraph("<b>AUDITOR PRINCIPAL</b>", ParagraphStyle('fs1', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("<b>REVISADO POR</b>", ParagraphStyle('fs2', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY_MID, alignment=TA_CENTER)),
        Paragraph("<b>ACEPTADO POR CLIENTE</b>", ParagraphStyle('fs3', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY_MID, alignment=TA_CENTER)),
    ],[
        Paragraph(" " * 30, ParagraphStyle('fl1', fontName='Helvetica', fontSize=9, alignment=TA_CENTER)),
        Paragraph(" " * 30, ParagraphStyle('fl2', fontName='Helvetica', fontSize=9, alignment=TA_CENTER)),
        Paragraph(" " * 30, ParagraphStyle('fl3', fontName='Helvetica', fontSize=9, alignment=TA_CENTER)),
    ],[
        Paragraph(audit_info['auditor'], ParagraphStyle('fn1', fontName='Helvetica-Bold', fontSize=9, textColor=GRAY_DARK, alignment=TA_CENTER)),
        Paragraph(audit_info.get('reviewer','—'), ParagraphStyle('fn2', fontName='Helvetica-Bold', fontSize=9, textColor=GRAY_DARK, alignment=TA_CENTER)),
        Paragraph(audit_info.get('client_contact','—'), ParagraphStyle('fn3', fontName='Helvetica-Bold', fontSize=9, textColor=GRAY_DARK, alignment=TA_CENTER)),
    ],[
        Paragraph("Purple Team Security", styles['PT_Small']),
        Paragraph("Purple Team Security", styles['PT_Small']),
        Paragraph(audit_info['client'], styles['PT_Small']),
    ],[
        Paragraph(f"Fecha: {audit_info['date']}", styles['PT_Small']),
        Paragraph(f"Fecha: {audit_info['date']}", styles['PT_Small']),
        Paragraph("Fecha: ___/___/______", styles['PT_Small']),
    ]]

    fw = CONTENT_W / 3
    firma_table = Table(firma_data, colWidths=[fw, fw, fw])
    firma_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), GRAY_LIGHT),
        ('BACKGROUND', (0,1), (-1,1), WHITE),
        ('BACKGROUND', (0,2), (-1,-1), GRAY_LIGHT),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LINEBELOW', (0,1), (-1,1), 1, GRAY_MID),
        ('GRID', (0,0), (-1,-1), 0.3, GRAY_BORDER),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [4,4,4,4]),
    ]))
    elems.append(firma_table)
    return elems


# ─── Datos de demostración ────────────────────────────────────────────────────
def get_demo_data():
    return {
        "audit_info": {
            "client": "Empresa Demo S.L.",
            "client_contact": "Carlos García (CTO)",
            "auditor": "Purple Team Security",
            "reviewer": "Purple Team Security",
            "ref": "PTS-2026-001",
            "date": datetime.now().strftime("%d/%m/%Y"),
            "start_date": "17/03/2026",
            "end_date": "21/03/2026",
            "audit_type": "Purple Team Assessment",
            "version": "v1.0 - Final",
            "scope_short": "Red WiFi corporativa · Aplicación web principal · Red interna",
            "scope_full": "Red WiFi corporativa (3 APs), aplicación web https://app.empresa-demo.com, segmento de red 192.168.1.0/24",
            "risk_score": 7.8,
            "severity_count": {"CRITICO": 2, "ALTO": 3, "MEDIO": 4, "BAJO": 2},
            "top_recommendations": [
                "Deshabilitar WPS inmediatamente en todos los puntos de acceso WiFi — riesgo crítico de acceso no autorizado.",
                "Implementar cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options) en la aplicación web principal.",
                "Actualizar el firmware del router principal (versión 2.1.3 con vulnerabilidad CVE-2024-1234 conocida).",
                "Segmentar la red interna con VLANs para limitar el movimiento lateral en caso de intrusión.",
                "Establecer un proceso de gestión de parches con ciclo mensual para todos los sistemas críticos.",
            ],
            "modules_summary": [
                {"area": "WiFi / Wireless", "module": "wifi_security_analyzer", "count": 4, "max_sev": "CRÍTICO", "status": "Completado"},
                {"area": "Aplicación Web", "module": "http_security_scanner",   "count": 3, "max_sev": "ALTO",    "status": "Completado"},
                {"area": "Red Interna",    "module": "network_recon",           "count": 4, "max_sev": "MEDIO",   "status": "Completado"},
            ],
            "mitre_techniques": [
                {"id": "T1595.001", "name": "Active Scanning: WiFi Scanning",      "tactic": "Reconocimiento", "ref": "F-01"},
                {"id": "T1190",     "name": "Exploit Public-Facing Application",   "tactic": "Acceso inicial", "ref": "F-03"},
                {"id": "T1046",     "name": "Network Service Discovery",           "tactic": "Descubrimiento", "ref": "F-06"},
                {"id": "T1592",     "name": "Gather Victim Host Information",      "tactic": "Reconocimiento", "ref": "F-04"},
                {"id": "T1590.002", "name": "Gather Victim Network Info: DNS",    "tactic": "Reconocimiento", "ref": "F-07"},
                {"id": "T1040",     "name": "Network Sniffing",                   "tactic": "Descubrimiento", "ref": "F-02"},
            ],
        },
        "findings": [
            {
                "title": "WPS habilitado en punto de acceso principal",
                "severity": "CRITICO",
                "cvss": "9.8",
                "mitre": "T1595.001",
                "area": "WiFi / Wireless",
                "description": "Se detectó el protocolo WPS (Wi-Fi Protected Setup) activo en el AP principal (SSID: Empresa-Corp). WPS es vulnerable a ataques de fuerza bruta de PIN que permiten obtener la contraseña WiFi en menos de 11.000 intentos, independientemente de la fortaleza de la contraseña WPA2.",
                "impact": "Un atacante en rango WiFi puede obtener las credenciales de la red corporativa en minutos utilizando herramientas como Reaver o Bully, obteniendo acceso completo a la red interna.",
                "evidence": "AP detectado: SSID=Empresa-Corp | BSSID=AA:BB:CC:DD:EE:FF | WPS=Enabled | WPS_State=Configured | Auth=WPA2-PSK",
                "recommendation": "Deshabilitar WPS en el panel de administración del AP (Inalámbrico > Configuración avanzada > WPS > Desactivar). Verificar también en APs secundarios. Considerar migración a WPA2-Enterprise con autenticación RADIUS.",
            },
            {
                "title": "Cifrado WEP detectado en red de invitados",
                "severity": "CRITICO",
                "cvss": "9.5",
                "mitre": "T1040",
                "area": "WiFi / Wireless",
                "description": "La red de invitados (SSID: Empresa-Guest) utiliza cifrado WEP (Wired Equivalent Privacy), un protocolo criptográfico roto desde 2001. El algoritmo RC4 utilizado por WEP es vulnerable a múltiples ataques estadísticos que permiten recuperar la clave en minutos.",
                "impact": "Cualquier atacante puede descifrar todo el tráfico WiFi de la red de invitados en menos de 5 minutos con herramientas estándar (aircrack-ng), comprometiendo la confidencialidad de los datos transmitidos.",
                "evidence": "SSID: Empresa-Guest | Encryption: WEP | Channel: 6 | Signal: -62dBm",
                "recommendation": "Migrar inmediatamente a WPA2 o WPA3. Deshabilitar la red de invitados hasta que se aplique la corrección. Considerar implementar un portal cautivo con WPA2-Enterprise para invitados.",
            },
            {
                "title": "Ausencia de cabeceras de seguridad HTTP críticas",
                "severity": "ALTO",
                "cvss": "7.5",
                "mitre": "T1190",
                "area": "Aplicación Web",
                "description": "La aplicación web principal (https://app.empresa-demo.com) no implementa las cabeceras de seguridad HTTP recomendadas por OWASP. Se detecta la ausencia de: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options y X-Content-Type-Options.",
                "impact": "La falta de HSTS expone a ataques SSL Stripping. La ausencia de CSP facilita ataques XSS. Sin X-Frame-Options la aplicación es vulnerable a Clickjacking. Puntuación de seguridad HTTP: F.",
                "evidence": "GET https://app.empresa-demo.com/ HTTP/1.1\nRespuesta: 200 OK\nServer: Apache/2.4.41\nX-Powered-By: PHP/7.4.3  [INFORMATION DISCLOSURE]\nHSTS: AUSENTE\nCSP: AUSENTE\nX-Frame-Options: AUSENTE",
                "recommendation": "Añadir en la configuración del servidor web (Apache/Nginx):\n  - Strict-Transport-Security: max-age=31536000; includeSubDomains\n  - Content-Security-Policy: default-src 'self'\n  - X-Frame-Options: DENY\n  - X-Content-Type-Options: nosniff\n  - Referrer-Policy: strict-origin-when-cross-origin",
            },
            {
                "title": "Versión de software con CVE conocida expuesta",
                "severity": "ALTO",
                "cvss": "8.1",
                "mitre": "T1592",
                "area": "Red Interna",
                "description": "El servidor web expone la versión exacta de software mediante la cabecera 'Server: Apache/2.4.41' y 'X-Powered-By: PHP/7.4.3'. Apache 2.4.41 tiene múltiples CVEs conocidas. PHP 7.4.3 alcanzó End-of-Life en noviembre 2022 y no recibe parches de seguridad.",
                "impact": "Un atacante puede identificar y explotar vulnerabilidades conocidas para las versiones detectadas, incluyendo RCE (Remote Code Execution) en versiones PHP afectadas.",
                "evidence": "Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3\nCVEs relevantes: CVE-2021-41773 (Apache path traversal), PHP 7.4 EOL",
                "recommendation": "1. Actualizar Apache a la última versión estable (2.4.62+). 2. Migrar a PHP 8.2 o superior. 3. Ocultar versiones: ServerTokens Prod (Apache) y expose_php = Off (PHP).",
            },
            {
                "title": "Puerto SSH (22) expuesto con autenticación por contraseña",
                "severity": "ALTO",
                "cvss": "7.2",
                "mitre": "T1046",
                "area": "Red Interna",
                "description": "El servidor principal (192.168.1.10) tiene el puerto SSH (22) abierto y acepta autenticación por contraseña. SSH con password authentication es vulnerable a ataques de fuerza bruta y credential stuffing.",
                "impact": "Un atacante con acceso a la red interna puede intentar ataques de fuerza bruta contra el servicio SSH para obtener acceso privilegiado al servidor.",
                "evidence": "192.168.1.10:22 OPEN\nSSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\nPasswordAuthentication: yes\nPermitRootLogin: sin confirmar",
                "recommendation": "1. Deshabilitar autenticación por contraseña (PasswordAuthentication no). 2. Usar exclusivamente claves SSH (RSA 4096 o Ed25519). 3. Cambiar puerto SSH a uno no estándar. 4. Implementar fail2ban. 5. Restringir acceso por IP con AllowUsers.",
            },
            {
                "title": "Cookies de sesión sin flags de seguridad",
                "severity": "MEDIO",
                "cvss": "5.3",
                "mitre": "T1190",
                "area": "Aplicación Web",
                "description": "Las cookies de sesión de la aplicación web no incluyen los flags de seguridad Secure, HttpOnly y SameSite. Esto expone las sesiones de usuario a robo mediante XSS o ataques Man-in-the-Middle.",
                "impact": "Un atacante puede robar tokens de sesión activos mediante JavaScript malicioso (XSS) o interceptación de tráfico HTTP.",
                "evidence": "Set-Cookie: PHPSESSID=abc123def456; path=/\n[MISSING: Secure, HttpOnly, SameSite flags]",
                "recommendation": "Configurar cookies con: Set-Cookie: session=valor; Secure; HttpOnly; SameSite=Strict; Path=/. En PHP: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Strict.",
            },
            {
                "title": "SSID por defecto del fabricante detectado",
                "severity": "BAJO",
                "cvss": "2.4",
                "mitre": "T1595.001",
                "area": "WiFi / Wireless",
                "description": "Se detectó una red WiFi con SSID genérico del fabricante (MOVISTAR_XXXX) en el entorno del cliente. Los SSIDs por defecto revelan el modelo del router y facilitan ataques dirigidos.",
                "impact": "Divulgación de información del fabricante y modelo del equipo, facilitando la búsqueda de vulnerabilidades específicas del dispositivo.",
                "evidence": "SSID: MOVISTAR_2A3F | Fabricante identificado: Askey | Modelo probable: RTF3505VW",
                "recommendation": "Cambiar el SSID por uno que no revele información de la organización ni del fabricante. Cambiar también la contraseña por defecto del panel de administración.",
            },
        ]
    }


# ─── Generador principal ──────────────────────────────────────────────────────
def generate_audit_report(audit_info, findings, output_path):
    styles = make_styles()
    hf = make_header_footer(audit_info)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        topMargin=MARGIN_T + 1*cm,
        bottomMargin=MARGIN_B + 1*cm,
        leftMargin=MARGIN_L,
        rightMargin=MARGIN_R,
        title=f"Informe de Auditoría - {audit_info['client']}",
        author="Purple Team Security",
        subject="Informe de Auditoría de Seguridad",
        creator="Purple Team Suite v2.0",
    )

    story = []
    story += cover_page(audit_info, styles)
    story += exec_summary(audit_info, styles)
    story += findings_section(findings, styles)
    story += mitre_section(audit_info, styles)
    story += remediation_section(findings, audit_info, styles)
    story += closing_section(audit_info, styles)

    doc.build(story, onFirstPage=hf, onLaterPages=hf)
    return output_path


# ─── Modo interactivo ─────────────────────────────────────────────────────────
def interactive_mode():
    print("\n🟣 PURPLE TEAM SUITE - Generador de Informes de Auditoría\n")
    print("Introduce los datos del informe (Enter para usar valor por defecto):\n")

    def ask(prompt, default=""):
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default

    today = datetime.now().strftime("%d/%m/%Y")
    ref   = f"PTS-{datetime.now().strftime('%Y-%m%d')}-001"

    client    = ask("Nombre del cliente", "Cliente S.L.")
    auditor   = ask("Nombre del auditor", "Purple Team Security")
    ref_val   = ask("Referencia del informe", ref)
    start_d   = ask("Fecha inicio auditoría (DD/MM/YYYY)", today)
    end_d     = ask("Fecha fin auditoría (DD/MM/YYYY)", today)
    audit_t   = ask("Tipo de auditoría", "Purple Team Assessment")
    scope_s   = ask("Alcance corto (1 línea)", "Red interna · Aplicación web")
    scope_f   = ask("Alcance completo", scope_s)
    contact   = ask("Contacto cliente (nombre + cargo)", "—")
    reviewer  = ask("Revisor del informe", auditor)

    # Hallazgos básicos en modo interactivo — usar datos de demo
    print("\n  ℹ️  Usando hallazgos de demostración. Para usar datos reales, ejecuta:")
    print(f"     python report_generator.py --session <ruta_sesion>\n")

    demo = get_demo_data()
    audit_info = demo['audit_info'].copy()
    audit_info.update({
        "client": client, "auditor": auditor, "ref": ref_val,
        "start_date": start_d, "end_date": end_d, "audit_type": audit_t,
        "scope_short": scope_s, "scope_full": scope_f,
        "client_contact": contact, "reviewer": reviewer,
        "date": today, "version": "v1.0 - Draft",
    })

    return audit_info, demo['findings']


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Purple Team Suite - Generador de Informes PDF")
    parser.add_argument("--demo",    action="store_true", help="Generar informe de demostración")
    parser.add_argument("--session", default="",          help="Ruta a directorio de sesión del orquestador")
    parser.add_argument("--output",  default="",          help="Ruta de salida del PDF")
    args = parser.parse_args()

    if args.demo:
        data = get_demo_data()
        audit_info = data['audit_info']
        findings   = data['findings']
    elif args.session:
        session_dir = Path(args.session)
        results_file = session_dir / "results_full.json"
        if not results_file.exists():
            print(f"❌ No se encontró results_full.json en {session_dir}")
            sys.exit(1)
        with open(results_file, encoding='utf-8') as f:
            session_data = json.load(f)
        # Adaptar datos del orquestador al formato del informe
        analysis = session_data.get('results', {}).get('analysis', {})
        sev = analysis.get('severity_breakdown', {"CRITICO":0,"ALTO":0,"MEDIO":0,"BAJO":0})
        audit_info = {
            "client": session_data.get('client', 'Cliente'),
            "auditor": "Purple Team Security",
            "reviewer": "Purple Team Security",
            "client_contact": "—",
            "ref": f"PTS-{datetime.now().strftime('%Y%m%d')}-001",
            "date": datetime.now().strftime("%d/%m/%Y"),
            "start_date": datetime.fromisoformat(session_data.get('start_time', datetime.now().isoformat())).strftime("%d/%m/%Y"),
            "end_date": datetime.now().strftime("%d/%m/%Y"),
            "audit_type": "Purple Team Assessment",
            "version": "v1.0 - Final",
            "scope_short": "Red WiFi · Aplicación Web · Red Interna",
            "scope_full": f"Sesión ID: {session_data.get('session_id','')}",
            "risk_score": analysis.get('risk_score', 0),
            "severity_count": sev,
            "top_recommendations": analysis.get('recommendations', [])[:5],
            "modules_summary": [
                {"area": mod, "module": mod, "count": len(data.get('findings',[])), "max_sev": "INFO", "status": data.get('status','Completado')}
                for mod, data in session_data.get('results', {}).items()
                if mod != 'analysis'
            ],
            "mitre_techniques": analysis.get('mitre_techniques_covered', []),
        }
        # Convertir hallazgos del orquestador
        raw_findings = analysis.get('all_findings', [])
        findings = [{"title": str(f.get('finding',''))[:80], "severity": "MEDIO",
                     "area": f.get('module',''), "description": str(f.get('finding','')),
                     "impact": "Evaluar impacto con el equipo de seguridad.",
                     "recommendation": "Revisar y aplicar las medidas de seguridad correspondientes."
                    } for f in raw_findings[:10]]
        if not findings:
            findings = get_demo_data()['findings']
    else:
        audit_info, findings = interactive_mode()

    # Determinar path de salida
    if args.output:
        out_path = Path(args.output)
    else:
        reports_dir = Path.home() / "storage" / "shared" / "Documents" / "purple_team_reports"
        if not reports_dir.parent.exists():
            reports_dir = Path.home() / "Documents" / "purple_team_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_client = audit_info['client'].replace(' ', '_').replace('/', '-')
        out_path = reports_dir / f"Informe_Auditoria_{safe_client}_{ts}.pdf"

    print(f"\n  📄 Generando informe: {out_path.name} ...")
    generate_audit_report(audit_info, findings, out_path)
    print(f"  ✅ Informe generado correctamente: {out_path}")
    return out_path


if __name__ == "__main__":
    main()
