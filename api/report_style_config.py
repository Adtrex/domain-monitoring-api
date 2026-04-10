"""Central style and copy configuration for PDF and DOCX report generation."""

from io import BytesIO
import re

REPORT_TEXT = {
    'title': 'CERRT Vulnerability Remediation Report',
    'how_to_use_title': 'HOW TO USE THIS REPORT',
    'findings_title': 'FINDINGS AND RECOMMENDED ACTIONS',
    'checks_title': 'ADDITIONAL SCAN CHECKS',
    'no_findings': 'No findings recorded for this scan.',
}

HOW_TO_USE_STEPS = [
    'Fix Critical and High findings first.',
    'Validate each fix in staging before production.',
    'Re-run scan to confirm issues are closed.',
]

PDF_STYLE = {
    'page': {
        'left_margin_mm': 14,
        'right_margin_mm': 14,
        'top_margin_mm': 14,
        'bottom_margin_mm': 14,
    },
    'fonts': {
        'title_size': 18,
        'section_size': 8,
        'body_size': 9,
        'small_size': 8,
        'meta_label_size': 7,
        'meta_value_size': 13,
    },
    'colors': {
        # Base palette
        'white': '#FFFFFF',
        'page_bg': '#F5F5F3',
        'surface': '#FFFFFF',
        'surface_secondary': '#F5F5F3',

        # Text
        'text_primary': '#1A1A18',
        'text_secondary': '#5F5E5A',
        'text_muted': '#888780',
        'text_hint': '#B4B2A9',

        # Borders
        'border': '#E0DFD8',
        'border_light': '#EEECEA',

        # Severity badge backgrounds and text (pill style)
        'severity': {
            'Critical': {
                'text': '#A32D2D',
                'bg': '#FCEBEB',
                'border': '#F7C1C1',
                'dot': '#E24B4A',
            },
            'High': {
                'text': '#854F0B',
                'bg': '#FAEEDA',
                'border': '#FAC775',
                'dot': '#EF9F27',
            },
            'Medium': {
                'text': '#185FA5',
                'bg': '#E6F1FB',
                'border': '#B5D4F4',
                'dot': '#378ADD',
            },
            'Low': {
                'text': '#3B6D11',
                'bg': '#EAF3DE',
                'border': '#C0DD97',
                'dot': '#639922',
            },
            'default': {
                'text': '#444441',
                'bg': '#F1EFE8',
                'border': '#D3D1C7',
                'dot': '#888780',
            },
        },

        # Stats grid
        'stat_label': '#888780',
        'stat_value': '#1A1A18',
        'stat_bg': '#F5F5F3',
        'stat_border': '#E0DFD8',

        # Finding card
        'card_bg': '#FFFFFF',
        'card_border': '#E0DFD8',
        'card_header_bg': '#F5F5F3',
        'action_box_bg': '#F5F5F3',

        # Section label
        'section_label': '#888780',

        # Status
        'status_completed': '#3B6D11',
        'link': '#185FA5',
    },
    'spacing': {
        'card_padding_mm': 4,
        'card_gap_mm': 3,
        'section_gap_mm': 5,
    },
}

DOCX_STYLE = {
    'stats_table_style': 'Table Grid',
    'finding_table_style': 'Light List Accent 1',
}

RISK_ORDER = {
    'Critical': 0,
    'High': 1,
    'Medium': 2,
    'Low': 3,
}

RISK_OWNER = {
    'Critical': 'Security / Platform team',
    'High': 'Security / Platform team',
    'Medium': 'Application team',
    'Low': 'Application team',
}


def risk_order(value):
    return RISK_ORDER.get(value or 'Low', 4)


def parse_remediation(recommendation):
    text = (recommendation or '').strip()
    if not text:
        return 'No remediation provided.', []

    links = re.findall(r'https?://[^\s)]+', text)
    cleaned = re.sub(r'https?://[^\s)]+', '', text).strip()
    if not cleaned:
        cleaned = 'Review the remediation resources listed below.'
    return cleaned, links


def findings_preview(findings, preview_size=None):
    ordered = sorted(
        findings,
        key=lambda item: (risk_order(item.get('risk_rating')), item.get('title', '')),
    )
    if preview_size is None:
        preview = ordered
    else:
        preview = ordered[:preview_size]
    remaining = max(len(ordered) - len(preview), 0)
    return ordered, preview, remaining


def _build_check_sections(payload):
    checks = payload.get('checks', {})
    return [
        ('Library Checks', checks.get('libraries', [])),
        ('Technology Checks', checks.get('technologies', [])),
        ('SSL/TLS Checks', checks.get('ssl', [])),
        ('Email Checks', checks.get('email', [])),
        ('Header Checks', checks.get('headers', [])),
        ('DNS Checks', checks.get('dns', [])),
    ]


def generate_pdf_report(payload):
    """Generate styled PDF report from payload data."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None, 'PDF export dependency missing. Install reportlab.'

    C = PDF_STYLE['colors']
    F = PDF_STYLE['fonts']
    SP = PDF_STYLE['spacing']

    summary = payload['summary']
    ordered, preview, _ = findings_preview(payload['findings'])

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=PDF_STYLE['page']['left_margin_mm'] * mm,
        rightMargin=PDF_STYLE['page']['right_margin_mm'] * mm,
        topMargin=PDF_STYLE['page']['top_margin_mm'] * mm,
        bottomMargin=PDF_STYLE['page']['bottom_margin_mm'] * mm,
    )
    styles = getSampleStyleSheet()

    # --- Typography styles ---
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=F['title_size'],
        leading=24,
        textColor=colors.HexColor(C['text_primary']),
        spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        'Meta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=F['small_size'],
        leading=12,
        textColor=colors.HexColor(C['text_muted']),
        spaceAfter=0,
    )
    section_label_style = ParagraphStyle(
        'SectionLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=F['section_size'],
        leading=11,
        textColor=colors.HexColor(C['section_label']),
        spaceBefore=SP['section_gap_mm'] * mm,
        spaceAfter=3,
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=F['body_size'],
        leading=13,
        textColor=colors.HexColor(C['text_primary']),
    )
    muted_body_style = ParagraphStyle(
        'MutedBody',
        parent=body_style,
        textColor=colors.HexColor(C['text_secondary']),
    )
    hint_style = ParagraphStyle(
        'Hint',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=F['small_size'],
        leading=11,
        textColor=colors.HexColor(C['text_hint']),
    )
    action_label_style = ParagraphStyle(
        'ActionLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=F['meta_label_size'],
        leading=10,
        textColor=colors.HexColor(C['text_muted']),
        spaceAfter=3,
    )
    link_style = ParagraphStyle(
        'Link',
        parent=body_style,
        textColor=colors.HexColor(C['link']),
        fontSize=F['small_size'],
    )
    small_style = ParagraphStyle(
        'Small',
        parent=body_style,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor(C['text_muted']),
    )

    story = []

    # === HEADER ===
    story.append(Paragraph(REPORT_TEXT['title'], title_style))
    status_color = C['status_completed']
    story.append(
        Paragraph(
            f"Generated {payload['generated_at']}  \u00b7  Scan #{summary['scan_id']}  \u00b7  "
            f"{summary['scan_type']}  \u00b7  "
            f"<font color='{status_color}'>{summary['status']}</font>  \u00b7  "
            f"{summary['total_assets_scanned']} asset checked",
            meta_style,
        )
    )
    story.append(Spacer(1, 8))

    # === STATS GRID ===
    stat_entries = [
        ('TOTAL', str(summary['total_findings']), C['text_primary']),
        ('CRITICAL', str(summary['critical_findings']), C['severity']['Critical']['text']),
        ('HIGH', str(summary['high_findings']), C['severity']['High']['text']),
        ('MEDIUM', str(summary['medium_findings']), C['severity']['Medium']['text']),
        ('LOW', str(summary['low_findings']), C['severity']['Low']['text']),
        ('ASSETS', str(summary['total_assets_scanned']), C['text_primary']),
    ]
    col_w = 29 * mm
    label_row = [
        Paragraph(f"<font color='{C['stat_label']}'><b>{lbl}</b></font>",
                  ParagraphStyle('SL', parent=styles['Normal'], fontName='Helvetica-Bold',
                                 fontSize=F['meta_label_size'], leading=10))
        for lbl, _, _ in stat_entries
    ]
    value_row = [
        Paragraph(f"<font color='{col}'><b>{val}</b></font>",
                  ParagraphStyle('SV', parent=styles['Normal'], fontName='Helvetica-Bold',
                                 fontSize=F['meta_value_size'], leading=18))
        for _, val, col in stat_entries
    ]
    stats_table = Table([label_row, value_row], colWidths=[col_w] * 6)
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(C['stat_bg'])),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor(C['stat_border'])),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor(C['border'])),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor(C['stat_bg'])]),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 10))

    # === HOW TO USE ===
    story.append(Paragraph(REPORT_TEXT['how_to_use_title'], section_label_style))

    inst_rows = []
    for idx, step in enumerate(HOW_TO_USE_STEPS, start=1):
        num_cell = Paragraph(
            f"<font color='{C['text_primary']}'><b>{idx}</b></font>",
            ParagraphStyle('InstNum', parent=styles['Normal'], fontName='Helvetica-Bold',
                           fontSize=F['body_size'], leading=13, alignment=1)
        )
        step_cell = Paragraph(step, muted_body_style)
        inst_rows.append([num_cell, step_cell])

    inst_table = Table(inst_rows, colWidths=[8 * mm, 166 * mm])
    inst_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(C['surface_secondary'])),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor(C['border'])),
        ('INNERGRID', (0, 0), (-1, -1), 0, colors.white),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('ROUNDEDCORNERS', [6, 6, 6, 6]),
    ]))
    story.append(inst_table)
    story.append(Spacer(1, 10))

    # === FINDINGS ===
    story.append(Paragraph(REPORT_TEXT['findings_title'], section_label_style))

    if not ordered:
        story.append(Paragraph(REPORT_TEXT['no_findings'], body_style))
    else:
        for index, finding in enumerate(preview, start=1):
            risk = finding.get('risk_rating') or 'Low'
            sev = C['severity'].get(risk, C['severity']['default'])
            owner = RISK_OWNER.get(risk, RISK_OWNER['Low'])
            remediation_text, remediation_links = parse_remediation(finding.get('recommendation'))

            # Badge cell — severity pill
            badge = Paragraph(
                f"<font color='{sev['text']}'><b>{risk}</b></font>",
                ParagraphStyle('Badge', parent=styles['Normal'], fontName='Helvetica-Bold',
                               fontSize=F['small_size'], leading=11, alignment=1)
            )

            # Number circle
            num_cell = Paragraph(
                f"<font color='{C['text_muted']}'><b>{index}</b></font>",
                ParagraphStyle('Num', parent=styles['Normal'], fontName='Helvetica-Bold',
                               fontSize=F['small_size'], leading=11, alignment=1)
            )

            title_cell = Paragraph(
                f"<b>{finding.get('title') or 'Untitled finding'}</b>",
                ParagraphStyle('FindingTitle', parent=styles['Normal'], fontName='Helvetica-Bold',
                               fontSize=F['body_size'], leading=13,
                               textColor=colors.HexColor(C['text_primary']))
            )

            def meta_row(key, val):
                return [
                    '',
                    Paragraph(
                        f"<font color='{C['text_muted']}'>{key}</font>",
                        ParagraphStyle('MK', parent=styles['Normal'], fontName='Helvetica',
                                       fontSize=F['small_size'], leading=12)
                    ),
                    Paragraph(
                        str(val),
                        ParagraphStyle('MV', parent=styles['Normal'], fontName='Helvetica',
                                       fontSize=F['small_size'], leading=12,
                                       textColor=colors.HexColor(C['text_secondary']))
                    ),
                    '',
                ]

            cves = '; '.join(finding.get('cve_ids') or []) or 'Not provided'
            asset = finding.get('asset') or 'N/A'
            category = finding.get('category') or 'Unknown'

            # Header row
            header_row = [num_cell, title_cell, badge]

            # Remediation section label
            action_label_cell = Paragraph('REMEDIATION', action_label_style)
            remediation_cell = Paragraph(
                remediation_text if remediation_text != 'No remediation provided.' else '',
                hint_style if remediation_text == 'No remediation provided.' else muted_body_style,
            )
            if remediation_text == 'No remediation provided.':
                remediation_cell = Paragraph(remediation_text, hint_style)

            card_rows = [
                # Header
                [num_cell, title_cell, badge],
                # Meta fields — use a nested sub-table for key/value pairs
            ]

            # Meta sub-table (Category, Asset, CVEs, Owner)
            meta_data = [
                ('Category', category),
                ('Affected asset', asset),
                ('Related CVEs', cves),
                ('Suggested owner', owner),
            ]
            meta_sub_rows = []
            for k, v in meta_data:
                meta_sub_rows.append([
                    Paragraph(k, ParagraphStyle('MK2', parent=styles['Normal'], fontName='Helvetica',
                                                fontSize=F['small_size'], leading=12,
                                                textColor=colors.HexColor(C['text_muted']))),
                    Paragraph(v, ParagraphStyle('MV2', parent=styles['Normal'], fontName='Helvetica',
                                                fontSize=F['small_size'], leading=12,
                                                textColor=colors.HexColor(C['text_secondary']))),
                ])

            meta_sub = Table(meta_sub_rows, colWidths=[28 * mm, 112 * mm])
            meta_sub.setStyle(TableStyle([
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('INNERGRID', (0, 0), (-1, -1), 0, colors.white),
                ('BOX', (0, 0), (-1, -1), 0, colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            # Remediation sub content
            rem_rows = [
                [Paragraph('REMEDIATION', action_label_style)],
                [remediation_cell],
            ]
            for link in remediation_links:
                rem_rows.append([
                    Paragraph(
                        f"<link href='{link}' color='{C['link']}'>{link}</link>",
                        ParagraphStyle('LinkStyle', parent=styles['Normal'], fontName='Helvetica',
                                       fontSize=F['small_size'], leading=12,
                                       textColor=colors.HexColor(C['link']))
                    )
                ])
            rem_sub = Table(rem_rows, colWidths=[144 * mm])
            rem_sub.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(C['action_box_bg'])),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('BOX', (0, 0), (-1, -1), 0, colors.white),
                ('INNERGRID', (0, 0), (-1, -1), 0, colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))

            outer_rows = [
                # Row 0: header (number | title | badge)
                [
                    Paragraph(f"<font color='{C['text_muted']}'><b>{index}</b></font>",
                              ParagraphStyle('N', parent=styles['Normal'], fontName='Helvetica-Bold',
                                             fontSize=F['small_size'], leading=11, alignment=1)),
                    title_cell,
                    badge,
                ],
                # Row 1: meta sub-table
                ['', meta_sub, ''],
                # Row 2: remediation sub-table
                ['', rem_sub, ''],
            ]

            card = Table(outer_rows, colWidths=[9 * mm, 144 * mm, 21 * mm])
            card.setStyle(TableStyle([
                # Outer card border
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor(C['card_border'])),
                ('ROUNDEDCORNERS', [6, 6, 6, 6]),

                # Header row bg
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(C['card_header_bg'])),

                # Body rows bg
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor(C['card_bg'])),

                # Remediation row bg
                ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor(C['card_bg'])),

                # Divider between header and meta
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor(C['border'])),

                # Divider between meta and remediation
                ('LINEABOVE', (0, 2), (-1, 2), 0.5, colors.HexColor(C['border'])),

                # Badge cell — pill background
                ('BACKGROUND', (2, 0), (2, 0), colors.HexColor(sev['bg'])),
                ('BOX', (2, 0), (2, 0), 0.5, colors.HexColor(sev['border'])),
                ('ROUNDEDCORNERS', [6, 6, 6, 6]),

                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, 0), 'CENTER'),

                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 7),

                # Tighter top/bottom on meta and remediation rows
                ('TOPPADDING', (0, 1), (-1, 2), 5),
                ('BOTTOMPADDING', (0, 1), (-1, 2), 5),

                # No padding on sub-table cells so they flush to card
                ('LEFTPADDING', (1, 1), (1, 2), 8),
                ('LEFTPADDING', (0, 1), (0, 2), 0),
                ('LEFTPADDING', (2, 1), (2, 2), 0),
            ]))

            story.append(card)
            story.append(Spacer(1, SP['card_gap_mm'] * mm))

        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                f"Showing all {len(ordered)} findings.",
                ParagraphStyle('Footer', parent=styles['Normal'], fontName='Helvetica',
                               fontSize=F['small_size'], leading=11,
                               textColor=colors.HexColor(C['text_hint']))
            )
        )

    # === ADDITIONAL CHECKS ===
    story.append(Spacer(1, 10))
    story.append(Paragraph(REPORT_TEXT['checks_title'], section_label_style))
    for section_name, section_items in _build_check_sections(payload):
        story.append(Paragraph(section_name, body_style))
        if not section_items:
            story.append(Paragraph('No records for this section.', hint_style))
            story.append(Spacer(1, 4))
            continue

        check_rows = [[
            Paragraph('<b>Name</b>', small_style),
            Paragraph('<b>Status / Version</b>', small_style),
            Paragraph('<b>Risk</b>', small_style),
            Paragraph('<b>Asset</b>', small_style),
        ]]
        for item in section_items:
            status_value = item.get('status') or item.get('detected_version') or item.get('version') or item.get('details') or 'Recorded'
            check_rows.append([
                Paragraph(str(item.get('name') or 'Unknown'), body_style),
                Paragraph(str(status_value), muted_body_style),
                Paragraph(str(item.get('risk_rating') or 'Low'), muted_body_style),
                Paragraph(str(item.get('asset') or 'N/A'), muted_body_style),
            ])

        check_table = Table(check_rows, colWidths=[50 * mm, 55 * mm, 22 * mm, 48 * mm])
        check_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor(C['border'])),
            ('INNERGRID', (0, 0), (-1, -1), 0.4, colors.HexColor(C['border_light'])),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(C['surface_secondary'])),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(check_table)
        story.append(Spacer(1, 6))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue(), None


def generate_docx_report(payload):
    """Generate styled DOCX report from payload data."""
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Mm
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
    except ImportError:
        return None, 'DOCX export dependency missing. Install python-docx.'

    C = PDF_STYLE['colors']

    def hex_to_rgb(hex_color):
        h = hex_color.lstrip('#')
        return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    def set_cell_bg(cell, hex_color):
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'auto')
        shd.set(qn('w:fill'), hex_color.lstrip('#'))
        tcPr.append(shd)

    def add_paragraph_with_color(doc_or_cell, text, font_size=9, bold=False, color_hex=None, italic=False):
        if hasattr(doc_or_cell, 'add_paragraph'):
            p = doc_or_cell.add_paragraph()
        else:
            p = doc_or_cell.paragraphs[0] if doc_or_cell.paragraphs else doc_or_cell.add_paragraph()
            p.clear()
        run = p.add_run(text)
        run.font.size = Pt(font_size)
        run.font.bold = bold
        run.font.italic = italic
        if color_hex:
            r, g, b = hex_to_rgb(color_hex)
            run.font.color.rgb = RGBColor(r, g, b)
        return p

    summary = payload['summary']
    ordered, preview, _ = findings_preview(payload['findings'])
    document = Document()

    # Narrow margins
    for section in document.sections:
        section.left_margin = Mm(14)
        section.right_margin = Mm(14)
        section.top_margin = Mm(14)
        section.bottom_margin = Mm(14)

    # === TITLE ===
    title_p = document.add_paragraph()
    title_run = title_p.add_run(REPORT_TEXT['title'])
    title_run.font.size = Pt(18)
    title_run.font.bold = True
    r, g, b = hex_to_rgb(C['text_primary'])
    title_run.font.color.rgb = RGBColor(r, g, b)

    # === META LINE ===
    meta_p = document.add_paragraph()
    meta_text = (
        f"Generated {payload['generated_at']}  \u00b7  Scan #{summary['scan_id']}  \u00b7  "
        f"{summary['scan_type']}  \u00b7  {summary['status']}  \u00b7  "
        f"{summary['total_assets_scanned']} asset checked"
    )
    meta_run = meta_p.add_run(meta_text)
    meta_run.font.size = Pt(8)
    r, g, b = hex_to_rgb(C['text_muted'])
    meta_run.font.color.rgb = RGBColor(r, g, b)

    document.add_paragraph()

    # === STATS TABLE ===
    stats = [
        ('TOTAL', str(summary['total_findings']), C['text_primary']),
        ('CRITICAL', str(summary['critical_findings']), C['severity']['Critical']['text']),
        ('HIGH', str(summary['high_findings']), C['severity']['High']['text']),
        ('MEDIUM', str(summary['medium_findings']), C['severity']['Medium']['text']),
        ('LOW', str(summary['low_findings']), C['severity']['Low']['text']),
        ('ASSETS', str(summary['total_assets_scanned']), C['text_primary']),
    ]
    stats_table = document.add_table(rows=2, cols=6)
    stats_table.style = 'Table Grid'
    for idx, (label, value, color) in enumerate(stats):
        label_cell = stats_table.cell(0, idx)
        set_cell_bg(label_cell, C['stat_bg'].lstrip('#'))
        add_paragraph_with_color(label_cell, label, font_size=7, bold=True, color_hex=C['stat_label'])

        val_cell = stats_table.cell(1, idx)
        set_cell_bg(val_cell, C['stat_bg'].lstrip('#'))
        add_paragraph_with_color(val_cell, value, font_size=13, bold=True, color_hex=color)

    document.add_paragraph()

    # === HOW TO USE ===
    how_p = document.add_paragraph()
    how_run = how_p.add_run(REPORT_TEXT['how_to_use_title'])
    how_run.font.size = Pt(8)
    how_run.font.bold = True
    r, g, b = hex_to_rgb(C['section_label'])
    how_run.font.color.rgb = RGBColor(r, g, b)

    for idx, step in enumerate(HOW_TO_USE_STEPS, start=1):
        p = document.add_paragraph(style='List Number')
        run = p.add_run(step)
        run.font.size = Pt(9)
        r, g, b = hex_to_rgb(C['text_secondary'])
        run.font.color.rgb = RGBColor(r, g, b)

    document.add_paragraph()

    # === FINDINGS ===
    findings_p = document.add_paragraph()
    findings_run = findings_p.add_run(REPORT_TEXT['findings_title'])
    findings_run.font.size = Pt(8)
    findings_run.font.bold = True
    r, g, b = hex_to_rgb(C['section_label'])
    findings_run.font.color.rgb = RGBColor(r, g, b)

    if not ordered:
        document.add_paragraph(REPORT_TEXT['no_findings'])
    else:
        for index, finding in enumerate(preview, start=1):
            risk = finding.get('risk_rating') or 'Low'
            sev = C['severity'].get(risk, C['severity']['default'])
            owner = RISK_OWNER.get(risk, RISK_OWNER['Low'])
            remediation_text, remediation_links = parse_remediation(finding.get('recommendation'))

            # Finding card table: 3 cols — number | details | badge
            card_table = document.add_table(rows=3, cols=3)
            card_table.style = 'Table Grid'

            # Row 0: header
            num_cell = card_table.cell(0, 0)
            set_cell_bg(num_cell, C['card_header_bg'].lstrip('#'))
            add_paragraph_with_color(num_cell, str(index), font_size=8, bold=True, color_hex=C['text_muted'])

            title_cell = card_table.cell(0, 1)
            set_cell_bg(title_cell, C['card_header_bg'].lstrip('#'))
            add_paragraph_with_color(title_cell, finding.get('title') or 'Untitled finding',
                                     font_size=9, bold=True, color_hex=C['text_primary'])

            badge_cell = card_table.cell(0, 2)
            set_cell_bg(badge_cell, sev['bg'].lstrip('#'))
            bp = add_paragraph_with_color(badge_cell, risk, font_size=8, bold=True, color_hex=sev['text'])
            bp.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Row 1: meta fields
            meta_fields = [
                ('Category', finding.get('category') or 'Unknown'),
                ('Affected asset', finding.get('asset') or 'N/A'),
                ('Related CVEs', '; '.join(finding.get('cve_ids') or []) or 'Not provided'),
                ('Suggested owner', owner),
            ]
            meta_cell = card_table.cell(1, 1)
            set_cell_bg(meta_cell, C['card_bg'].lstrip('#'))
            meta_cell.paragraphs[0].clear()
            for k, v in meta_fields:
                mp = meta_cell.add_paragraph()
                key_run = mp.add_run(f"{k}: ")
                key_run.font.size = Pt(8)
                key_run.font.bold = False
                r, g, b = hex_to_rgb(C['text_muted'])
                key_run.font.color.rgb = RGBColor(r, g, b)
                val_run = mp.add_run(v)
                val_run.font.size = Pt(8)
                r, g, b = hex_to_rgb(C['text_secondary'])
                val_run.font.color.rgb = RGBColor(r, g, b)

            for col_idx in [0, 2]:
                set_cell_bg(card_table.cell(1, col_idx), C['card_bg'].lstrip('#'))

            # Row 2: remediation
            rem_cell = card_table.cell(2, 1)
            set_cell_bg(rem_cell, C['action_box_bg'].lstrip('#'))
            rem_cell.paragraphs[0].clear()

            label_run_p = rem_cell.add_paragraph()
            label_r = label_run_p.add_run('REMEDIATION')
            label_r.font.size = Pt(7)
            label_r.font.bold = True
            r, g, b = hex_to_rgb(C['text_muted'])
            label_r.font.color.rgb = RGBColor(r, g, b)

            rem_p = rem_cell.add_paragraph()
            rem_r = rem_p.add_run(remediation_text)
            rem_r.font.size = Pt(8)
            rem_r.font.italic = (remediation_text == 'No remediation provided.')
            r, g, b = hex_to_rgb(C['text_hint'] if remediation_text == 'No remediation provided.' else C['text_secondary'])
            rem_r.font.color.rgb = RGBColor(r, g, b)

            for link in remediation_links:
                lp = rem_cell.add_paragraph()
                lr = lp.add_run(link)
                lr.font.size = Pt(8)
                r, g, b = hex_to_rgb(C['link'])
                lr.font.color.rgb = RGBColor(r, g, b)

            for col_idx in [0, 2]:
                set_cell_bg(card_table.cell(2, col_idx), C['action_box_bg'].lstrip('#'))

            document.add_paragraph()

        footer_p = document.add_paragraph()
        footer_run = footer_p.add_run(f'Showing all {len(ordered)} findings.')
        footer_run.font.size = Pt(8)
        r, g, b = hex_to_rgb(C['text_hint'])
        footer_run.font.color.rgb = RGBColor(r, g, b)

    # === ADDITIONAL CHECKS ===
    checks_heading = document.add_paragraph()
    checks_run = checks_heading.add_run(REPORT_TEXT['checks_title'])
    checks_run.font.size = Pt(8)
    checks_run.font.bold = True
    r, g, b = hex_to_rgb(C['section_label'])
    checks_run.font.color.rgb = RGBColor(r, g, b)

    for section_name, section_items in _build_check_sections(payload):
        section_p = document.add_paragraph()
        section_r = section_p.add_run(section_name)
        section_r.font.size = Pt(9)
        section_r.font.bold = True

        if not section_items:
            note = document.add_paragraph('No records for this section.')
            note.runs[0].italic = True
            continue

        table = document.add_table(rows=1, cols=4)
        table.style = 'Table Grid'
        headers = ['Name', 'Status / Version', 'Risk', 'Asset']
        for idx, text in enumerate(headers):
            table.cell(0, idx).text = text

        for item in section_items:
            row = table.add_row().cells
            status_value = item.get('status') or item.get('detected_version') or item.get('version') or item.get('details') or 'Recorded'
            row[0].text = str(item.get('name') or 'Unknown')
            row[1].text = str(status_value)
            row[2].text = str(item.get('risk_rating') or 'Low')
            row[3].text = str(item.get('asset') or 'N/A')

        document.add_paragraph()

    buffer = BytesIO()
    document.save(buffer)
    buffer.seek(0)
    return buffer.getvalue(), None