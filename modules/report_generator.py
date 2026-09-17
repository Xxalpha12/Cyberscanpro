"""
CyberScan Pro - Complete Report Generator
Generates both HTML and PDF reports with plain English explanations.
"""

import os
import html as _html
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from modules.logger import get_logger

logger = get_logger(__name__)

OUTPUT_DIR   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

METHODOLOGY = [
    ("1. Subdomain Discovery",  "Queried public APIs and performed DNS bruteforce",           "Hidden attack surfaces and exposed subdomains"),
    ("2. Network Scanning",     "TCP port scan using Nmap/socket scanner",                    "Open ports, running services, software versions"),
    ("3. Service Detection",    "Banner grabbing and version fingerprinting on all open ports","Outdated software, vulnerable service versions"),
    ("4. Web Assessment",       "HTTP security header analysis and vulnerability payload testing","XSS, SQLi, CSRF, directory traversal, open redirects"),
    ("5. CVE Mapping",          "Queried the NVD (National Vulnerability Database) API",      "Known CVEs matching detected service versions with CVSS scores"),
    ("6. Risk Scoring",         "Calculated per-host risk scores based on finding severity",  "Overall security posture and prioritised remediation list"),
]

VULN_EXPLANATIONS = {
    "Missing Security Header: X-Frame-Options": {
        "what": "This website is missing a security instruction that prevents it from being secretly embedded inside another webpage.",
        "means": "An attacker can create a fake webpage that silently loads your site inside it. When a visitor clicks something on the fake page, they are unknowingly clicking on your site — this is called Clickjacking.",
        "impact": "Attackers can trick users into clicking Delete Account, Send Money, or Grant Access buttons on your site without them realizing it.",
        "fix": "Add this line to your web server configuration:\n  X-Frame-Options: SAMEORIGIN\nThis tells browsers to never allow your site to be loaded inside another site's frame.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: Content-Security-Policy": {
        "what": "The website has no Content Security Policy — a set of rules telling the browser what content is allowed to load.",
        "means": "Without this policy, an attacker who finds any vulnerability can inject and run malicious scripts that steal user data or redirect visitors.",
        "impact": "If an attacker injects JavaScript into your page, it runs completely unchecked — potentially stealing login cookies, credit card numbers, or personal data from every visitor.",
        "fix": "Add this header to your server:\n  Content-Security-Policy: default-src 'self'\nThis only allows content from your own domain.",
        "difficulty": "Medium — requires testing"
    },
    "Missing Security Header: Strict-Transport-Security": {
        "what": "The website is not enforcing HTTPS connections, which means the first visit from a user can be intercepted.",
        "means": "Even if your site supports HTTPS, attackers on the same network can intercept the first request and downgrade it to unencrypted HTTP.",
        "impact": "On public Wi-Fi, attackers can steal passwords and session cookies from your users before they even connect securely.",
        "fix": "Add this header:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains\nThis tells browsers to always use HTTPS for your site.",
        "difficulty": "Easy — 5 minute fix"
    },
    "Missing Security Header: X-Content-Type-Options": {
        "what": "The website is missing a header that prevents browsers from guessing the type of files being served.",
        "means": "Browsers sometimes try to guess file types. If an attacker uploads a file disguised as an image but containing malicious code, the browser might execute it.",
        "impact": "Attackers can upload malicious files that get executed as scripts when viewed by other users.",
        "fix": "Add this header:\n  X-Content-Type-Options: nosniff",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: X-XSS-Protection": {
        "what": "The website is missing a legacy browser-level protection against Cross-Site Scripting attacks.",
        "means": "Older browsers have a built-in XSS filter that needs this header to activate. Without it, some browsers will not attempt to block script injection attacks.",
        "impact": "Users on older browsers are more vulnerable to script injection attacks that can steal their session and personal data.",
        "fix": "Add this header:\n  X-XSS-Protection: 1; mode=block",
        "difficulty": "Easy — 2 minute fix"
    },
    "Missing Security Header: Referrer-Policy": {
        "what": "The website does not control what information is shared when users click links to other websites.",
        "means": "When a user clicks a link leaving your site, their browser automatically tells the next site the full URL they came from — including any sensitive data in the URL.",
        "impact": "Private tokens, user IDs, or session data in URLs can be leaked to third-party websites without the user's knowledge.",
        "fix": "Add this header:\n  Referrer-Policy: strict-origin-when-cross-origin",
        "difficulty": "Easy — 2 minute fix"
    },
    "SQL Injection": {
        "what": "The website passes user input directly into database queries without checking or sanitizing it first.",
        "means": "An attacker can type specially crafted text into a form or URL that manipulates your database — instead of searching for a username, they can extract all usernames and passwords.",
        "impact": "Attackers can steal your entire database, delete all records, bypass login, or take complete control of the database server.",
        "fix": "Never build database queries by combining strings with user input. Use parameterized queries:\n  WRONG:  'SELECT * FROM users WHERE name = ' + userInput\n  RIGHT:  'SELECT * FROM users WHERE name = ?', [userInput]",
        "difficulty": "Medium — requires code changes"
    },
    "Cross-Site Scripting (XSS)": {
        "what": "The website displays user-submitted content without checking it for malicious code first.",
        "means": "An attacker can submit JavaScript code through a form or URL. When other users view that page, the malicious script runs in their browser as if it came from your website.",
        "impact": "Attackers can steal session cookies, redirect users to fake login pages, make the browser perform actions on behalf of the user, or install malware.",
        "fix": "Always encode user input before displaying it on a page. Use HTML escaping on all user-submitted data and implement a Content-Security-Policy header.",
        "difficulty": "Medium — requires code review"
    },
    "Missing CSRF Protection": {
        "what": "Forms on this website do not include a secret token to verify that submissions come from legitimate users.",
        "means": "An attacker can create a hidden form on their site that submits to your website. When a logged-in user visits the attacker's page, their browser silently submits the form.",
        "impact": "Attackers can make users unknowingly transfer money, change passwords, delete accounts, or perform any action the user is authorized to do.",
        "fix": "Add a unique CSRF token to every form and verify it on the server before processing any submission.",
        "difficulty": "Medium — requires code changes"
    },
    "Directory Traversal": {
        "what": "The website allows file paths in URLs that can be manipulated to access files outside the intended folder.",
        "means": "By typing ../ in a URL, an attacker can trick the server into reading files it should never expose — like configuration files containing passwords.",
        "impact": "Attackers can read database credentials, API keys, private keys, and system configuration files from the server.",
        "fix": "Never use user-supplied input directly in file system paths. Always validate that the resolved path starts with your intended base directory.",
        "difficulty": "Medium — requires code changes"
    },
    "Open Redirect": {
        "what": "The website redirects users to URLs specified in request parameters without validating them.",
        "means": "Attackers can send users a link to your trusted website that secretly redirects them to a malicious site. Because the link starts with your domain, users trust it.",
        "impact": "Highly effective phishing attacks — users trust your domain name but end up on a fake login page controlled by the attacker.",
        "fix": "Never redirect to user-supplied URLs. Use a whitelist of allowed redirect destinations or only allow relative paths within your own domain.",
        "difficulty": "Easy — requires code change"
    },
}

def get_explanation(vuln_type):
    if vuln_type in VULN_EXPLANATIONS:
        return VULN_EXPLANATIONS[vuln_type]
    for key, val in VULN_EXPLANATIONS.items():
        if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
            return val
    return {
        "what":   f"A security vulnerability of type '{vuln_type}' was detected on the target.",
        "means":  "This vulnerability could be exploited by an attacker to compromise the security of the target system or its users.",
        "impact": "The specific impact depends on the nature of the vulnerability and the attacker's objectives.",
        "fix":    "Review the technical evidence provided and consult security documentation for this vulnerability type. Consider engaging a qualified security professional for remediation.",
        "difficulty": "Review required"
    }


class ReportGenerator:

    def __init__(self, session_id, target, hosts, web_findings,
                 cve_findings, output_format="both", enrichment=None):
        self.session_id    = session_id
        self.target        = target
        self.hosts         = hosts
        self.web_findings  = self._enrich(web_findings)
        self.cve_findings  = cve_findings
        self.output_format = output_format
        self.generated_at  = datetime.now()
        self.enrichment    = enrichment or {}
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def _enrich(self, findings):
        enriched = []
        for f in findings:
            exp = get_explanation(f.get("vuln_type", ""))
            f = dict(f)
            f["plain_what"]       = exp["what"]
            f["plain_means"]      = exp["means"]
            f["plain_impact"]     = exp["impact"]
            f["plain_fix"]        = exp["fix"]
            f["plain_difficulty"] = exp["difficulty"]
            enriched.append(f)
        return enriched

    def _severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.web_findings + self.cve_findings:
            sev = f.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _risk_rating(self, counts):
        if counts["Critical"] > 0: return "CRITICAL"
        if counts["High"] > 0:     return "HIGH"
        if counts["Medium"] > 0:   return "MEDIUM"
        if counts["Low"] > 0:      return "LOW"
        return "INFORMATIONAL"

    def _all_findings(self):
        merged = []
        for f in self.web_findings:
            merged.append({
                "severity":       f.get("severity"),
                "vuln_type":      f.get("vuln_type"),
                "host_ip":        f.get("host_ip"),
                "recommendation": f.get("recommendation", f.get("plain_fix","")),
            })
        for f in self.cve_findings:
            merged.append({
                "severity":       f.get("severity"),
                "vuln_type":      f.get("cve_id"),
                "host_ip":        f.get("host_ip"),
                "recommendation": f"Update {f.get('service','')} to the latest patched version. Search {f.get('cve_id','')} at nvd.nist.gov.",
            })
        return sorted(merged, key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4))

    def _data_uri(self, path, mime):
        """Base64-embed an image so the saved report stays viewable even when
        opened offline or after the Flask app is no longer reachable."""
        try:
            import base64
            with open(path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            return f"data:{mime};base64,{b64}"
        except Exception:
            return None

    def _context(self):
        counts = self._severity_counts()

        logo_path = os.path.join(os.path.dirname(OUTPUT_DIR), "static", "logo.jpeg")
        logo_data_uri = self._data_uri(logo_path, "image/jpeg")

        screenshot_path = os.path.join(OUTPUT_DIR, "screenshots", f"screenshot_{self.session_id}.png")
        screenshot_data_uri = self._data_uri(screenshot_path, "image/png")

        return {
            "report_title":    "Vulnerability Assessment Report",
            "target":          self.target,
            "session_id":      self.session_id,
            "generated_at":    self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_hosts":     len(self.hosts),
            "total_findings":  len(self.web_findings) + len(self.cve_findings),
            "risk_rating":     self._risk_rating(counts),
            "severity_counts": counts,
            "hosts":           self.hosts,
            "web_findings":    sorted(self.web_findings,  key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4)),
            "cve_findings":    sorted(self.cve_findings,  key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"), 4)),
            "all_findings":    self._all_findings(),
            "methodology":     METHODOLOGY,
            "enrichment":      self.enrichment,
            "shodan":          self.enrichment.get("shodan", {}),
            "virustotal":      self.enrichment.get("virustotal", {}),
            "abuseipdb":       self.enrichment.get("abuseipdb", {}),
            "urlscan":         self.enrichment.get("urlscan", {}),
            "has_enrichment":  bool(self.enrichment),
            "logo_data_uri":       logo_data_uri,
            "screenshot_data_uri": screenshot_data_uri,
        }

    def generate(self):
        paths = []
        ts   = self.generated_at.strftime("%Y%m%d_%H%M%S")
        base = f"cyberscanpro_report_{self.session_id}_{ts}"

        if self.output_format in ("html", "both"):
            p = os.path.join(OUTPUT_DIR, f"{base}.html")
            self._html(p)
            paths.append(p)

        if self.output_format in ("pdf", "both"):
            p = os.path.join(OUTPUT_DIR, f"{base}.pdf")
            self._pdf(p)
            paths.append(p)

        return paths

    def _html(self, path):
        env  = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"])
        )
        tmpl = env.get_template("report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(tmpl.render(**self._context()))
        logger.info(f"HTML report: {path}")

    def _pdf(self, path):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, HRFlowable,
                                            PageBreak, KeepTogether, Image as RLImage)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            from reportlab.platypus.flowables import Flowable
        except ImportError:
            logger.error("reportlab not installed — PDF skipped")
            return

        ctx = self._context()

        NAVY    = colors.HexColor("#1F3864")
        BLUE    = colors.HexColor("#2E75B6")
        LBLUE   = colors.HexColor("#EBF3FB")
        CRIT    = colors.HexColor("#C00000")
        HIGH    = colors.HexColor("#E74C3C")
        MED     = colors.HexColor("#E67E22")
        LOW_C   = colors.HexColor("#2980B9")
        GREEN   = colors.HexColor("#27AE60")
        NONE_C  = colors.HexColor("#95A5A6")

        SEV_C = {"Critical": CRIT, "High": HIGH, "Medium": MED, "Low": LOW_C, "None": NONE_C}
        RISK_C = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": LOW_C, "INFORMATIONAL": GREEN}

        # Reserve a footer band on every page for "CONFIDENTIAL | page N" —
        # avoids relying on emoji/unicode the base font can't render.
        def _footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(colors.HexColor("#8A97A8"))
            canvas.drawString(2*cm, 1.3*cm,
                f"CyberScan Pro  ·  FUPRE Final Year Project  ·  Obeh Emmanuel Onoriode (COS/9581/2022)")
            canvas.drawRightString(A4[0]-2*cm, 1.3*cm, f"Page {doc_.page}")
            canvas.setStrokeColor(colors.HexColor("#DDDDDD"))
            canvas.line(2*cm, 1.6*cm, A4[0]-2*cm, 1.6*cm)
            canvas.restoreState()

        doc = SimpleDocTemplate(path, pagesize=A4,
            topMargin=1.6*cm, bottomMargin=2.2*cm,
            leftMargin=2*cm, rightMargin=2*cm,
            title="CyberScan Pro Report", author="Obeh Emmanuel Onoriode")

        FONT = "Helvetica"
        def S(name, **kw):
            from reportlab.lib.styles import ParagraphStyle
            kw.setdefault("fontName", FONT)
            return ParagraphStyle(name, **kw)

        TITLE = S("T",  fontSize=19, textColor=colors.white, fontName="Helvetica-Bold")
        SUB   = S("SB", fontSize=9,  textColor=colors.HexColor("#A8C4D8"))
        H1    = S("H1", fontSize=13, textColor=NAVY, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)
        H2    = S("H2", fontSize=10.5, textColor=BLUE, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
        BD    = S("BD", fontSize=9,  leading=14, spaceAfter=6, alignment=TA_JUSTIFY)
        SM    = S("SM", fontSize=7.5, textColor=colors.grey, leading=11)
        LB    = S("LB", fontSize=8,  textColor=colors.grey, fontName="Helvetica-Bold")
        PE    = S("PE", fontSize=8.5, leading=13, spaceAfter=3)
        TC    = S("TC", fontSize=8,  leading=11.5)                    # table cell body text
        TCB   = S("TCB",fontSize=8,  leading=11.5, fontName="Helvetica-Bold")  # table cell header

        def sp(h=0.3): return Spacer(1, h*cm)
        def hr(): return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC"))
        def cell(txt, style=TC): return Paragraph(esc(txt), style)  # wrap plain text so tables wrap correctly instead of overflowing
        def esc(txt):
            # Reportlab's Paragraph parses a subset of HTML — unescaped scan data
            # (evidence, URLs, NVD descriptions) can contain '<', '>', '&' and would
            # otherwise be silently swallowed or break the layout. Escape first,
            # then callers may re-insert their OWN trusted <b>/<br/> tags around it.
            return _html.escape(str(txt), quote=False)

        story = []

        # ── COVER ──────────────────────────────────────────────────────────
        risk     = ctx["risk_rating"]
        risk_col = RISK_C.get(risk, NONE_C)
        counts   = ctx["severity_counts"]

        logo_path = os.path.join(os.path.dirname(OUTPUT_DIR), "static", "logo.jpeg")
        logo_cell = ""
        if os.path.exists(logo_path):
            try:
                logo_cell = RLImage(logo_path, width=1.1*cm, height=1.1*cm)
            except Exception:
                logo_cell = ""

        header_row = [logo_cell, Paragraph("CyberScan Pro", TITLE)] if logo_cell else [Paragraph("CyberScan Pro", TITLE)]
        header_widths = [1.6*cm, 15.4*cm] if logo_cell else [17*cm]
        cover_head = Table([header_row], colWidths=header_widths)
        cover_head.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), NAVY),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 14),
            ("BOTTOMPADDING", (0,0),(-1,-1), 14),
            ("LEFTPADDING",   (0,0),(0,-1), 16),
        ]))

        cover_sub = Table([[Paragraph("Vulnerability Assessment Report — Automated Security Scan", SUB)]], colWidths=[17*cm])
        cover_sub.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#16233d")),
            ("TOPPADDING",    (0,0),(-1,-1), 7),
            ("BOTTOMPADDING", (0,0),(-1,-1), 7),
            ("LEFTPADDING",   (0,0),(0,-1), 16),
        ]))

        # Meta grid: target / generated / session on the left, risk badge + stats on the right
        meta_left = Table([
            [Paragraph("TARGET", LB)], [Paragraph(f"<b>{esc(ctx['target'])}</b>", S("MV", fontSize=11, fontName="Helvetica-Bold"))],
            [sp(0.15)],
            [Paragraph("GENERATED", LB)], [Paragraph(ctx["generated_at"], TC)],
            [sp(0.15)],
            [Paragraph("SESSION ID", LB)], [Paragraph(ctx["session_id"], TC)],
        ], colWidths=[8*cm])
        meta_left.setStyle(TableStyle([
            ("TOPPADDING",(0,0),(-1,-1),1), ("BOTTOMPADDING",(0,0),(-1,-1),1), ("LEFTPADDING",(0,0),(-1,-1),0),
        ]))

        risk_badge = Table([[Paragraph(f"RISK: {risk}", S("RB", fontSize=11, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER))]], colWidths=[8*cm])
        risk_badge.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), risk_col),
            ("TOPPADDING",(0,0),(-1,-1),8), ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ]))
        stat_row = Table([
            [Paragraph("HOSTS", LB), Paragraph("FINDINGS", LB), Paragraph("CRITICAL", LB), Paragraph("HIGH", LB)],
            [Paragraph(str(ctx["total_hosts"]), S("SV", fontSize=15, fontName="Helvetica-Bold")),
             Paragraph(str(ctx["total_findings"]), S("SV", fontSize=15, fontName="Helvetica-Bold")),
             Paragraph(str(counts["Critical"]), S("SVC", fontSize=15, fontName="Helvetica-Bold", textColor=CRIT)),
             Paragraph(str(counts["High"]), S("SVH", fontSize=15, fontName="Helvetica-Bold", textColor=HIGH))],
        ], colWidths=[2*cm]*4)
        stat_row.setStyle(TableStyle([
            ("ALIGN",(0,0),(-1,-1),"CENTER"), ("TOPPADDING",(0,0),(-1,-1),3), ("BOTTOMPADDING",(0,0),(-1,-1),3),
        ]))
        meta_right = Table([[risk_badge],[sp(0.25)],[stat_row]], colWidths=[8*cm])
        meta_right.setStyle(TableStyle([("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))

        cover_meta = Table([[meta_left, meta_right]], colWidths=[8.5*cm, 8.5*cm])
        cover_meta.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.white),
            ("BOX",           (0,0),(-1,-1), 1, colors.HexColor("#E2E8F0")),
            ("TOPPADDING",    (0,0),(-1,-1), 16),
            ("BOTTOMPADDING", (0,0),(-1,-1), 16),
            ("LEFTPADDING",   (0,0),(0,-1), 16),
            ("RIGHTPADDING",  (1,0),(1,-1), 16),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))

        story += [cover_head, cover_sub, cover_meta, sp(0.5)]

        # ── TARGET SCREENSHOT (flows right under the cover, same page if it fits) ──
        screenshot_path = os.path.join(OUTPUT_DIR, "screenshots", f"screenshot_{self.session_id}.png")
        if os.path.exists(screenshot_path):
            try:
                from PIL import Image as PILImage
                with PILImage.open(screenshot_path) as im:
                    iw, ih = im.size
                max_w = 17 * cm
                display_h = min(max_w * (ih / iw), 9*cm)
                display_w = display_h * (iw/ih) if display_h == 9*cm else max_w
                story += [
                    Paragraph("Target Screenshot", H1), hr(), sp(0.15),
                    RLImage(screenshot_path, width=display_w, height=display_h),
                    sp(0.3),
                ]
            except Exception as e:
                logger.warning(f"Could not embed screenshot in PDF: {e}")

        story.append(PageBreak())

        # ── PLAIN ENGLISH GUIDE ────────────────────────────────────────────
        story += [Paragraph("What This Report Means", H1), hr(), sp(0.2),
                  Paragraph("This report was generated by CyberScan Pro after scanning <b>" + esc(ctx['target']) + "</b>. It identifies security weaknesses that could be exploited by attackers. <b>You do not need to be a technical expert to understand this report.</b> Every finding includes a plain English explanation of what the problem is, what could happen if exploited, and exactly how to fix it.", BD), sp(0.2)]

        guide = Table([
            [cell("CRITICAL", TCB), cell("HIGH", TCB), cell("MEDIUM", TCB), cell("LOW", TCB)],
            [cell("Fix within 24 hours", SM), cell("Fix within 7 days", SM), cell("Fix within 30 days", SM), cell("Fix when possible", SM)],
            [cell("Attackers can fully compromise the system or steal all data", TC),
             cell("Significant damage or data breach likely", TC),
             cell("Moderate risk, specific conditions required to exploit", TC),
             cell("Minor risk, limited direct impact", TC)]
        ], colWidths=[4.25*cm]*4)
        guide.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(0,-1), colors.HexColor("#fff0f0")),
            ("BACKGROUND",    (1,0),(1,-1), colors.HexColor("#fff5f0")),
            ("BACKGROUND",    (2,0),(2,-1), colors.HexColor("#fffbf0")),
            ("BACKGROUND",    (3,0),(3,-1), colors.HexColor("#f0f6ff")),
            ("TEXTCOLOR",     (0,0),(0,1), CRIT), ("TEXTCOLOR",(1,0),(1,1), HIGH),
            ("TEXTCOLOR",     (2,0),(2,1), MED),  ("TEXTCOLOR",(3,0),(3,1), LOW_C),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#DDDDDD")),
            ("TOPPADDING",    (0,0),(-1,-1), 7),
            ("BOTTOMPADDING", (0,0),(-1,-1), 7),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story += [guide, sp(0.3)]

        # ── EXECUTIVE SUMMARY ──────────────────────────────────────────────
        story += [Paragraph("Executive Summary", H1), hr(), sp(0.2)]
        summ = (f"An automated vulnerability assessment was conducted against <b>{esc(ctx['target'])}</b> on {ctx['generated_at']}. "
                f"The scan discovered <b>{ctx['total_hosts']}</b> live host(s) with <b>{ctx['total_findings']}</b> security findings. "
                f"The overall risk is rated <b>{risk}</b>. ")
        if counts["Critical"] > 0:
            summ += f"<b>{counts['Critical']} CRITICAL issue(s) require immediate action within 24 hours.</b> "
        if counts["High"] > 0:
            summ += f"{counts['High']} HIGH severity issue(s) should be resolved within 7 days. "
        if ctx["total_findings"] == 0:
            summ += "No vulnerabilities were detected — the target appears well-secured against the tested attack vectors."
        story += [Paragraph(summ, BD), sp(0.3)]

        # ── METHODOLOGY ────────────────────────────────────────────────────
        story += [Paragraph("Scan Methodology", H1), hr(), sp(0.2)]
        mdata = [[cell("Phase", TCB), cell("What Was Done", TCB), cell("What We Looked For", TCB)]] + \
                [[cell(m[0]), cell(m[1]), cell(m[2])] for m in ctx["methodology"]]
        mt = Table(mdata, colWidths=[3.4*cm, 6.8*cm, 6.8*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), NAVY),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("RIGHTPADDING",  (0,0),(-1,-1), 6),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
        story += [mt, PageBreak()]

        # ── HOSTS ──────────────────────────────────────────────────────────
        if ctx["hosts"]:
            story += [Paragraph("Discovered Hosts and Open Services", H1), hr(), sp(0.2),
                      Paragraph("The following hosts and open ports were discovered. Each open port represents a service accessible from the internet.", BD), sp(0.1)]
            for host in ctx["hosts"]:
                host_block = [Paragraph(f"<b>{esc(host['ip'])}</b> — {esc(host.get('hostname','N/A'))} — OS: {esc(host.get('os','Unknown'))}", H2)]
                if host.get("ports"):
                    pd = [[cell("Port", TCB), cell("Service", TCB), cell("Version", TCB), cell("Security Note", TCB)]]
                    for p in host["ports"]:
                        port = p.get("port", 0)
                        note = {22:"Ensure key-based auth, disable root login",
                                21:"FTP is unencrypted — use SFTP instead",
                                23:"Telnet is unencrypted — disable immediately",
                                80:"Redirect all traffic to HTTPS (port 443)",
                                443:"Ensure TLS 1.2+ only, disable old SSL",
                                3306:"MySQL publicly exposed — restrict by firewall",
                                3389:"RDP exposed — restrict to specific IPs only",
                                6379:"Redis exposed — verify authentication enabled",
                               }.get(port, "Verify this port needs public access")
                        pd.append([cell(f"{port}/{p.get('protocol','tcp')}"),
                                   cell(p.get("service","")), cell(str(p.get("version",""))[:30]), cell(note)])
                    pt = Table(pd, colWidths=[2*cm,2.3*cm,4.2*cm,8.5*cm])
                    pt.setStyle(TableStyle([
                        ("BACKGROUND",    (0,0),(-1,0), NAVY),
                        ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                        ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                        ("TOPPADDING",    (0,0),(-1,-1), 5),
                        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                        ("LEFTPADDING",   (0,0),(-1,-1), 6),
                        ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ]))
                    host_block.append(pt)
                host_block.append(sp(0.35))
                story.append(KeepTogether(host_block))

        # ── WEB FINDINGS ───────────────────────────────────────────────────
        if ctx["web_findings"]:
            story += [Paragraph("Web Application Security Findings", H1), hr(), sp(0.2),
                      Paragraph("Each finding below includes a plain English explanation — what the problem is, what an attacker could do with it, and exactly how to fix it.", BD), sp(0.25)]

            for i, f in enumerate(ctx["web_findings"], 1):
                sev = f.get("severity","Low")
                sc  = SEV_C.get(sev, NONE_C)

                block = []
                hdr = Table([[
                    Paragraph(f"<b>{i}. {esc(f.get('vuln_type',''))}</b>",
                              S("FH", fontSize=10, textColor=colors.HexColor("#111"),
                                fontName="Helvetica-Bold")),
                    Paragraph(sev, S("SV", fontSize=9, textColor=sc,
                                     fontName="Helvetica-Bold", alignment=1))
                ]], colWidths=[14*cm, 3*cm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#f8f9fa")),
                    ("TOPPADDING",    (0,0),(-1,-1), 8),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 8),
                    ("LEFTPADDING",   (0,0),(0,-1), 10),
                    ("LINEBELOW",     (0,0),(-1,0), 2, sc),
                ]))
                block.append(hdr)

                pe = Table([
                    [Paragraph("<b>What is this vulnerability?</b>", LB),
                     Paragraph("<b>What does it mean for "+esc(ctx['target'])+"?</b>", LB)],
                    [Paragraph(f.get("plain_what",""), PE),
                     Paragraph(f.get("plain_means",""), PE)],
                    [Paragraph("<b>What could an attacker do?</b>", LB),
                     Paragraph("<b>How to fix it</b>", LB)],
                    [Paragraph(f.get("plain_impact",""), PE),
                     Paragraph(f.get("plain_fix","") + (f"<br/><br/><b>Difficulty:</b> {f.get('plain_difficulty','')}" if f.get("plain_difficulty") else ""), PE)],
                ], colWidths=[8.5*cm, 8.5*cm])
                pe.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#f0f8ff")),
                    ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#dde8f0")),
                    ("TOPPADDING",    (0,0),(-1,-1), 6),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                    ("LEFTPADDING",   (0,0),(-1,-1), 8),
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ("LINEAFTER",     (0,0),(0,-1), 0.5, colors.HexColor("#c0d8ee")),
                ]))
                block.append(pe)

                td = Table([
                    [Paragraph("<b>Technical Details (for developers)</b>", LB), ""],
                    [cell("URL:", TCB),       cell(str(f.get("url",""))[:90])],
                    [cell("Evidence:", TCB), cell(str(f.get("evidence","N/A"))[:90])],
                ], colWidths=[3*cm, 14*cm])
                td.setStyle(TableStyle([
                    ("GRID",          (0,1),(-1,-1), 0.3, colors.HexColor("#EEEEEE")),
                    ("TOPPADDING",    (0,0),(-1,-1), 4),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                    ("LEFTPADDING",   (0,0),(-1,-1), 6),
                    ("SPAN",          (0,0),(-1,0)),
                ]))
                block.append(td)
                block.append(sp(0.35))
                story.append(KeepTogether(block))

        # ── CVE FINDINGS ───────────────────────────────────────────────────
        if ctx["cve_findings"]:
            story += [Paragraph("Known Software Vulnerabilities (CVEs)", H1), hr(), sp(0.2),
                      Paragraph("These are publicly documented security flaws found in software running on <b>"+esc(ctx['target'])+"</b>. Because they are publicly known, automated hacking tools actively scan the internet looking for servers running these versions.", BD),
                      Paragraph("Automated attack tools scan for these vulnerabilities around the clock. Update the affected software immediately.", S("W", fontSize=9, textColor=CRIT, fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=10)), sp(0.15)]

            cve_data = [[cell("CVE ID",TCB), cell("Host",TCB), cell("Port",TCB), cell("Service",TCB), cell("CVSS",TCB), cell("Severity",TCB)]]
            for f in ctx["cve_findings"]:
                cve_data.append([cell(f.get("cve_id","")), cell(f.get("host_ip","")),
                                  cell(str(f.get("port",""))), cell(str(f.get("service",""))[:20]),
                                  cell(str(f.get("cvss_score",""))), cell(f.get("severity",""))])
            ct = Table(cve_data, colWidths=[3.5*cm,3*cm,1.5*cm,3.5*cm,1.5*cm,4*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ]))
            story += [ct, sp(0.3)]

            for f in ctx["cve_findings"]:
                score = float(f.get("cvss_score") or 0)
                if score >= 9.0:   danger = "EXTREMELY DANGEROUS — attacker can likely take full control of the system."
                elif score >= 7.0: danger = "HIGHLY DANGEROUS — can lead to significant data theft or system compromise."
                elif score >= 4.0: danger = "MODERATELY DANGEROUS — exploitation requires specific conditions but can lead to a breach."
                else:              danger = "LOW RISK — limited direct impact but should still be patched."

                sev = f.get("severity","Low")
                sc  = SEV_C.get(sev, NONE_C)
                cve_block = [
                    Paragraph(f"<b>{esc(f.get('cve_id',''))} — CVSS {esc(f.get('cvss_score',''))}/10 ({sev})</b>",
                              S("CH", fontSize=9, textColor=sc, fontName="Helvetica-Bold", spaceBefore=8)),
                    Paragraph(f"<b>Danger level:</b> {danger}", PE),
                    Paragraph(f"<b>Description:</b> {esc(f.get('description','See NVD for details.'))[:250]}", PE),
                    Paragraph(f"<b>Fix:</b> Update <b>{esc(f.get('service',''))}</b> to the latest version. Visit nvd.nist.gov and search for <b>{esc(f.get('cve_id',''))}</b> for specific patch information.", PE),
                    sp(0.15)
                ]
                story.append(KeepTogether(cve_block))

        # ── ACTION PLAN ────────────────────────────────────────────────────
        story += [Paragraph("Your Action Plan — What To Do Next", H1), hr(), sp(0.2),
                  Paragraph("Address these security issues in the following order. Start at the top and work down:", BD), sp(0.15)]

        if ctx["all_findings"]:
            ap = [[cell("#",TCB), cell("Issue",TCB), cell("Severity",TCB), cell("Action Required",TCB)]]
            for i, f in enumerate(ctx["all_findings"][:10], 1):
                ap.append([cell(str(i)),
                           cell(f.get("vuln_type","")[:40]),
                           cell(f.get("severity","")),
                           cell(f.get("recommendation","Fix this issue.")[:70])])
            apt = Table(ap, colWidths=[0.8*cm, 6*cm, 2.5*cm, 7.7*cm])
            apt.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LBLUE]),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#CCCCCC")),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ]))
            story.append(apt)
        else:
            story.append(Paragraph("No immediate actions required. Re-scan periodically to detect new vulnerabilities.", BD))

        story += [sp(0.6),
                  Paragraph("This report is confidential and intended for authorized use only. It reflects the security posture of the "
                            "target at the time of the scan; new vulnerabilities may emerge afterward.", SM)]

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        logger.info(f"PDF report: {path}")
