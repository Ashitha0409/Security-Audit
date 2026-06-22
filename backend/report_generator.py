"""PDF Report Generator for PRAWL"""
import os
from datetime import datetime, timezone


def generate_pdf_report(scan_result, output_dir=None):
    """Generate a professional PDF security report."""
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(output_dir, exist_ok=True)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        import re

        # ── Unicode font registration ──────────────────────────────────────
        # Try to register a Unicode-capable font for Hindi/regional language support.
        # Falls back to Helvetica (English only) if font files not found.
        UNICODE_FONT = 'Helvetica'
        UNICODE_FONT_BOLD = 'Helvetica-Bold'

        font_candidates = [
            # Windows system fonts
            ('C:/Windows/Fonts/arial.ttf',        'C:/Windows/Fonts/arialbd.ttf'),
            ('C:/Windows/Fonts/NotoSans-Regular.ttf', 'C:/Windows/Fonts/NotoSans-Bold.ttf'),
            # Linux
            ('/usr/share/fonts/truetype/freefont/FreeSans.ttf',
             '/usr/share/fonts/truetype/freefont/FreeSansBold.ttf'),
            ('/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf',
             '/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf'),
            # macOS
            ('/System/Library/Fonts/Supplemental/Arial.ttf',
             '/System/Library/Fonts/Supplemental/Arial Bold.ttf'),
        ]

        for regular, bold in font_candidates:
            if os.path.exists(regular) and os.path.exists(bold):
                try:
                    pdfmetrics.registerFont(TTFont('UniFont', regular))
                    pdfmetrics.registerFont(TTFont('UniFont-Bold', bold))
                    UNICODE_FONT = 'UniFont'
                    UNICODE_FONT_BOLD = 'UniFont-Bold'
                    break
                except Exception:
                    continue

        # ── Filename ───────────────────────────────────────────────────────
        # ✅ FIX: renamed from cybershield_ to prawl_
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename  = f"prawl_report_{scan_result['hostname']}_{timestamp}.pdf"
        filepath  = os.path.join(output_dir, filename)

        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        # ── Colours ────────────────────────────────────────────────────────
        BLACK     = colors.HexColor('#0a0a0f')
        BLUE      = colors.HexColor('#0ea5e9')
        GREY      = colors.HexColor('#374151')
        LIGHTGREY = colors.HexColor('#f3f4f6')
        RED       = colors.HexColor('#ef4444')
        ORANGE    = colors.HexColor('#f97316')
        YELLOW    = colors.HexColor('#f59e0b')
        GREEN     = colors.HexColor('#22c55e')
        WHITE     = colors.white

        # ── Styles ─────────────────────────────────────────────────────────
        h1_style = ParagraphStyle(
            'H1', fontName=UNICODE_FONT_BOLD, fontSize=13,
            textColor=BLUE, spaceAfter=8, spaceBefore=16
        )
        body_style = ParagraphStyle(
            'Body', fontName=UNICODE_FONT, fontSize=9,
            textColor=GREY, spaceAfter=6, leading=14
        )

        story = []

        # ── Translations ───────────────────────────────────────────────────
        lang = scan_result.get('language', 'english').lower()
        t = {
            'report_title': 'Security Audit Report' if lang == 'english' else 'सुरक्षा ऑडिट रिपोर्ट',
            'score_label': 'SECURITY SCORE' if lang == 'english' else 'सुरक्षा स्कोर',
            'risk_level': 'Risk Level:' if lang == 'english' else 'जोखिम का स्तर:',
            'crit': 'CRITICAL' if lang == 'english' else 'गंभीर',
            'warn': 'WARNINGS' if lang == 'english' else 'चेतावनियाँ',
            'pass': 'PASSED' if lang == 'english' else 'पास हुए',
            'tot': 'TOTAL CHECKS' if lang == 'english' else 'कुल जाँच',
            'details': 'Detailed Security Findings' if lang == 'english' else 'विस्तृत सुरक्षा निष्कर्ष',
            'fix': 'HOW TO FIX:' if lang == 'english' else 'कैसे ठीक करें:',
            'adv_title': 'Advanced Vulnerability Scan & OSINT' if lang == 'english' else 'उन्नत भेद्यता स्कैन और ओसिंट (OSINT)',
            'compliance_title': 'DPDP Compliance Readiness' if lang == 'english' else 'डीपीडीपी अनुपालन तैयारी',
            'dpdp_readiness': 'DPDP READINESS SCORE' if lang == 'english' else 'डीपीडीपी तैयारी स्कोर',
            'no_compliance_gaps': 'No compliance gaps detected — good security posture.' if lang == 'english' else 'कोई अनुपालन अंतर नहीं मिला — अच्छी सुरक्षा स्थिति।',
            'attack_title': 'Attack-Path Exploitability' if lang == 'english' else 'अटैक-पाथ शोषण क्षमता',
            'exploit_risk': 'EXPLOITABILITY RISK' if lang == 'english' else 'शोषण जोखिम',
            'verified_path': 'Verified attack path' if lang == 'english' else 'सत्यापित हमला पथ',
            'no_attack_path': 'No viable attack path to a customer-data breach was found from the current findings.' if lang == 'english' else 'वर्तमान निष्कर्षों से ग्राहक-डेटा उल्लंघन तक कोई व्यवहार्य हमला पथ नहीं मिला।',
            'phishing_title': 'Lookalike / Phishing-Domain Watch' if lang == 'english' else 'फिशिंग-डोमेन निगरानी',
            'no_impersonators': 'No active impersonator domains detected. Continue scanning regularly.' if lang == 'english' else 'कोई सक्रिय नकलची डोमेन नहीं मिला। नियमित रूप से स्कैन जारी रखें।',
        }

        def _clean(text):
            """Strip non-BMP chars (emoji) and escape for ReportLab's XML-ish markup."""
            text = re.sub(r'[^\u0000-\uFFFF]', '', str(text or ''))
            return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')

        # ── Header banner ──────────────────────────────────────────────────
        # ✅ FIX: CyberShield → PRAWL
        header_data = [[
            Paragraph(
                '<font color="white"><b>PRAWL</b></font>',
                ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=22, textColor=WHITE)
            ),
            Paragraph(
                f'<font color="#0ea5e9">{t["report_title"]}</font><br/>'
                f'<font color="#9ca3af" size="8">{scan_result["scanned_at"]}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT, fontSize=11, textColor=BLUE)
            )
        ]]
        header_table = Table(header_data, colWidths=[9*cm, 8*cm])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BLACK),
            ('PADDING',    (0, 0), (-1, -1), 12),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Score section ──────────────────────────────────────────────────
        score       = scan_result['score']
        score_color = RED if score < 40 else (ORANGE if score < 60 else (YELLOW if score < 80 else GREEN))

        # ✅ FIX: Escape AI summary text and replace newlines to prevent overlapping/XML errors
        import re
        ai_summary_text = scan_result.get('ai_summary', '')
        ai_summary_text = re.sub(r'[^\u0000-\uFFFF]', '', ai_summary_text)  # Remove emojis that cause '?' symbols
        ai_summary_text = ai_summary_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')

        score_data = [[
            Paragraph(
                f'<font color="{score_color.hexval()}" size="36"><b>{score}</b></font><br/>'
                f'<font color="#9ca3af" size="9">{t["score_label"]}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=36, alignment=TA_CENTER)
            ),
            Paragraph(
                f'<font color="#111827" size="11"><b>{t["risk_level"]} {scan_result["risk_level"]}</b></font><br/><br/>'
                f'<font color="#4b5563" size="9">{ai_summary_text}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT, fontSize=9, leading=14)
            ),
        ]]
        score_table = Table(score_data, colWidths=[4*cm, 13*cm])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), LIGHTGREY),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#f9fafb')),
            ('PADDING',    (0, 0), (-1, -1), 14),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX',        (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Stats row ──────────────────────────────────────────────────────
        stats = scan_result.get('stats', {'critical': 0, 'warnings': 0, 'passed': 0, 'total': 0})
        stat_items = [
            (str(stats.get('critical', 0)), t['crit'], '#ef4444'),
            (str(stats.get('warnings', 0)), t['warn'], '#f59e0b'),
            (str(stats.get('passed', 0)),   t['pass'], '#22c55e'),
            (str(stats.get('total', 0)),    t['tot'],  '#0ea5e9'),
        ]
        stat_data = [[
            Paragraph(
                f'<font color="{c}" size="20"><b>{v}</b></font><br/>'
                f'<font color="#6b7280" size="8">{l}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT_BOLD, alignment=TA_CENTER)
            ) for v, l, c in stat_items
        ]]
        stat_table = Table(stat_data, colWidths=[4.25*cm] * 4)
        stat_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), LIGHTGREY),
            ('TOPPADDING',    (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX',           (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('LINEBEFORE',    (1, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
        ]))
        story.append(stat_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Findings ───────────────────────────────────────────────────────
        story.append(Paragraph(t['details'], h1_style))

        sev_colors = {
            'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b',
            'low': '#3b82f6', 'none': '#22c55e', 'info': '#6b7280'
        }
        status_labels = {
            'pass': 'PASS', 'fail': 'FAIL', 'warning': 'WARN',
            'error': 'ERROR', 'info': 'INFO'
        }
        status_icons = {
            'pass': '✓', 'fail': '✗', 'warning': '⚠', 'error': '?', 'info': 'i'
        }

        for f in scan_result['findings']:
            sev          = f.get('severity', 'info')
            color_hex    = sev_colors.get(sev, '#6b7280')
            status_label = status_labels.get(f['status'], f['status'].upper())
            status_icon  = status_icons.get(f['status'], '?')

            row_data = [[
                Paragraph(
                    f'<font color="{color_hex}"><b>{status_icon} {status_label}</b></font>',
                    ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=9, alignment=TA_CENTER)
                ),
                Paragraph(
                    f'<b>{f["check"]}</b>',
                    ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=9)
                ),
                Paragraph(
                    str(f.get('details', '')).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>'),
                    ParagraphStyle('', fontName=UNICODE_FONT, fontSize=8,
                                   textColor=colors.HexColor('#4b5563'), leading=12)
                ),
            ]]
            row_color = (
                colors.HexColor('#fff7f7') if f['status'] == 'fail'
                else colors.HexColor('#fffbf0') if f['status'] == 'warning'
                else colors.HexColor('#f0fff4')
            )
            row_table = Table(row_data, colWidths=[2.5*cm, 5.5*cm, 9*cm])
            row_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), row_color),
                ('PADDING',    (0, 0), (-1, -1), 8),
                ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
                ('BOX',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ]))
            story.append(row_table)

            if f.get('fix'):
                fix_data = [[
                    Paragraph(
                        t['fix'],
                        ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=7, textColor=BLUE)
                    ),
                    Paragraph(
                        str(f.get('fix', '')).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>'),
                        ParagraphStyle('', fontName=UNICODE_FONT, fontSize=8,
                                       textColor=GREY, leading=12)
                    ),
                ]]
                fix_table = Table(fix_data, colWidths=[2.5*cm, 14.5*cm])
                fix_table.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#eff6ff')),
                    ('PADDING',       (0, 0), (-1, -1), 6),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(fix_table)
            story.append(Spacer(1, 0.2*cm))

        # ── DPDP Compliance Section (Feature 1) ─────────────────────────────
        compliance = scan_result.get('compliance') or {}
        if compliance:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph(t['compliance_title'], h1_style))

            readiness = compliance.get('readiness_score', 100)
            r_color = RED if readiness < 40 else (ORANGE if readiness < 60 else (YELLOW if readiness < 80 else GREEN))
            story.append(Paragraph(
                f'<font color="{r_color.hexval()}" size="20"><b>{readiness}/100</b></font> '
                f'<font color="#6b7280" size="9">{t["dpdp_readiness"]}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT_BOLD, spaceAfter=8)
            ))

            hits = compliance.get('hits', [])
            if hits:
                for h in hits:
                    crore = round(h.get('penalty_ceiling_inr', 0) / 10000000)
                    hit_status = h.get('status', 'partial')
                    status_color = RED if hit_status == 'gap' else YELLOW
                    hit_data = [[
                        Paragraph(
                            f'<font color="{status_color.hexval()}"><b>{hit_status.upper()}</b></font>',
                            ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8, alignment=TA_CENTER)
                        ),
                        Paragraph(
                            f"<b>{_clean(h.get('clause', ''))}</b><br/>"
                            f"<font size='7' color='#6b7280'>{_clean(h.get('law', ''))}</font><br/>"
                            f"{_clean(h.get('rationale', ''))}",
                            body_style
                        ),
                        Paragraph(
                            f"up to Rs.{crore} crore",
                            ParagraphStyle('', fontName=UNICODE_FONT, fontSize=8, alignment=TA_CENTER, textColor=GREY)
                        ),
                    ]]
                    hit_table = Table(hit_data, colWidths=[2.5*cm, 11*cm, 3.5*cm])
                    hit_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1),
                         colors.HexColor('#fff7f7') if hit_status == 'gap' else colors.HexColor('#fffbf0')),
                        ('PADDING',    (0, 0), (-1, -1), 8),
                        ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
                        ('BOX',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                    ]))
                    story.append(hit_table)
                    story.append(Spacer(1, 0.15*cm))
            else:
                story.append(Paragraph(t['no_compliance_gaps'], body_style))

            if compliance.get('brief'):
                story.append(Spacer(1, 0.1*cm))
                story.append(Paragraph(_clean(compliance['brief']), body_style))

            if compliance.get('disclaimer'):
                story.append(Paragraph(
                    f"<i>{_clean(compliance['disclaimer'])}</i>",
                    ParagraphStyle('', fontName=UNICODE_FONT, fontSize=7,
                                   textColor=colors.HexColor('#9ca3af'), spaceBefore=4)
                ))

        # ── Attack-Path Exploitability Section (Features 2 & 3) ─────────────
        exploit = scan_result.get('exploit') or {}
        if exploit:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph(t['attack_title'], h1_style))

            risk = exploit.get('risk', 0)
            risk_color = RED if risk >= 80 else (ORANGE if risk >= 60 else (YELLOW if risk >= 40 else GREEN))
            story.append(Paragraph(
                f'<font color="{risk_color.hexval()}" size="20"><b>{risk}/100</b></font> '
                f'<font color="#6b7280" size="9">{t["exploit_risk"]}</font>',
                ParagraphStyle('', fontName=UNICODE_FONT_BOLD, spaceAfter=8)
            ))

            best_path = exploit.get('best_path')
            if exploit.get('reachable') and best_path:
                path_str = ' &rarr; '.join(_clean(n) for n in best_path.get('path', []))
                story.append(Paragraph(
                    f"<b>{t['verified_path']}:</b> {path_str} "
                    f"<font color='#6b7280'>({int(best_path.get('confidence', 0) * 100)}% confidence)</font>",
                    body_style
                ))
                if exploit.get('narrative'):
                    story.append(Paragraph(_clean(exploit['narrative']), body_style))
            else:
                story.append(Paragraph(t['no_attack_path'],
                                        ParagraphStyle('', fontName=UNICODE_FONT, fontSize=9, textColor=GREEN)))

        # ── Phishing / Lookalike Domain Watch Section (Feature 4) ────────────
        impersonators = scan_result.get('impersonators') or []
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(t['phishing_title'], h1_style))
        if impersonators:
            for imp in impersonators:
                threat = imp.get('threat', 0)
                threat_color = RED if threat >= 70 else (ORANGE if threat >= 40 else YELLOW)
                imp_data = [[
                    Paragraph(f"<b>{_clean(imp.get('domain', ''))}</b>",
                              ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=9)),
                    Paragraph(
                        f"Cert: {'Yes' if imp.get('has_cert') else 'No'} | Resolves: {'Yes' if imp.get('resolves') else 'No'}",
                        body_style
                    ),
                    Paragraph(
                        f'<font color="{threat_color.hexval()}"><b>{threat}/100</b></font>',
                        ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=9, alignment=TA_CENTER)
                    ),
                ]]
                imp_table = Table(imp_data, colWidths=[6*cm, 7*cm, 4*cm])
                imp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fff7f7')),
                    ('PADDING',    (0, 0), (-1, -1), 8),
                    ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
                    ('BOX',        (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ]))
                story.append(imp_table)
                story.append(Spacer(1, 0.15*cm))
        else:
            story.append(Paragraph(t['no_impersonators'],
                                    ParagraphStyle('', fontName=UNICODE_FONT, fontSize=9, textColor=GREEN)))

        # ── Advanced Scan OSINT / Docker Findings ──────────────────────────
        adv = scan_result.get('advanced_scan', {})
        if adv:
            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph(t['adv_title'], h1_style))
            
            nmap = adv.get('nmap', {})
            if nmap and not nmap.get('error'):
                risks = nmap.get('risk_findings', [])
                if risks:
                    for r in risks:
                        adv_data = [[
                            Paragraph(f'<font color="{RED.hexval()}"><b>NMAP: DANGEROUS PORT</b></font>', ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8)),
                            Paragraph(f"<b>Port {r.get('port')} ({r.get('service')})</b><br/>{str(r.get('description', '')).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(chr(10), '<br/>')}", body_style)
                        ]]
                        t = Table(adv_data, colWidths=[3.5*cm, 13.5*cm])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fff7f7')),
                            ('BOX', (0,0), (-1,-1), 0.5, RED),
                            ('VALIGN', (0,0), (-1,-1), 'TOP'),
                            ('PADDING', (0,0), (-1,-1), 8)
                        ]))
                        story.append(t)
                        story.append(Spacer(1, 0.1*cm))
            
            nikto = adv.get('nikto', {})
            if nikto and not nikto.get('error'):
                vulns = nikto.get('vulnerabilities', [])
                if vulns:
                    for v in vulns:
                        sev_color = RED if v.get('severity') == 'critical' else (ORANGE if v.get('severity') == 'high' else YELLOW)
                        adv_data = [[
                            Paragraph(f'<font color="{sev_color.hexval()}"><b>NIKTO FINDING</b></font>', ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8)),
                            Paragraph(f"<b>{v.get('severity').upper()}</b>: {str(v.get('description', '')).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace(chr(10), '<br/>')}", body_style)
                        ]]
                        t = Table(adv_data, colWidths=[3.5*cm, 13.5*cm])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fafafa')),
                            ('BOX', (0,0), (-1,-1), 0.5, sev_color),
                            ('VALIGN', (0,0), (-1,-1), 'TOP'),
                            ('PADDING', (0,0), (-1,-1), 8)
                        ]))
                        story.append(t)
                        story.append(Spacer(1, 0.1*cm))
                        
            sql = adv.get('sqlmap', {})
            if sql and not sql.get('error') and not sql.get('skipped'):
                if sql.get('injectable'):
                    adv_data = [[
                        Paragraph(f'<font color="{RED.hexval()}"><b>SQL INJECTION</b></font>', ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8)),
                        Paragraph(f"<b>DB: {sql.get('dbms')}</b><br/>Vulnerable params: {', '.join(sql.get('parameters', []))}", body_style)
                    ]]
                    t = Table(adv_data, colWidths=[3.5*cm, 13.5*cm])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fff7f7')),
                        ('BOX', (0,0), (-1,-1), 0.5, RED),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                        ('PADDING', (0,0), (-1,-1), 8)
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.1*cm))
            
            ww = adv.get('whatweb', {})
            if ww and not ww.get('error'):
                plugins = ww.get('plugins', [])
                if plugins:
                    ww_text = ", ".join([f"{p['name']} (v{p['version']})" if p['version'] else p['name'] for p in plugins])
                    adv_data = [[
                        Paragraph(f'<font color="{BLUE.hexval()}"><b>TECH STACK</b></font>', ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8)),
                        Paragraph(ww_text, body_style)
                    ]]
                    t = Table(adv_data, colWidths=[3.5*cm, 13.5*cm])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f0f9ff')),
                        ('BOX', (0,0), (-1,-1), 0.5, BLUE),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                        ('PADDING', (0,0), (-1,-1), 8)
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.1*cm))
                    
            crt = adv.get('crt_sh', {})
            if crt and not crt.get('error') and crt.get('count', 0) > 0:
                subs = crt.get('subdomains', [])
                if len(subs) > 8:
                    subs = subs[:8] + [f"... and {len(subs)-8} more"]
                adv_data = [[
                    Paragraph(f'<font color="{GREEN.hexval()}"><b>OSINT Subdomains</b></font>', ParagraphStyle('', fontName=UNICODE_FONT_BOLD, fontSize=8)),
                    Paragraph(", ".join(subs), body_style)
                ]]
                t = Table(adv_data, colWidths=[3.5*cm, 13.5*cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f0fff4')),
                    ('BOX', (0,0), (-1,-1), 0.5, GREEN),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('PADDING', (0,0), (-1,-1), 8)
                ]))
                story.append(t)
                story.append(Spacer(1, 0.1*cm))

        # ── Footer ─────────────────────────────────────────────────────────
        # ✅ FIX: CyberShield → PRAWL
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            f'Generated by PRAWL — Know Before They Do | {scan_result["scanned_at"]} | For: {scan_result["url"]}',
            ParagraphStyle('', fontName=UNICODE_FONT, fontSize=7,
                           textColor=colors.HexColor('#9ca3af'), alignment=TA_CENTER)
        ))

        doc.build(story)
        return filename

    except ImportError:
        return None