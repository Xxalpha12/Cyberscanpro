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
            from reportlab.lib.styles import ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, HRFlowable,
                                            PageBreak, KeepTogether, Image as RLImage)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
            from reportlab.graphics.shapes import Drawing, Wedge, Circle, String
        except ImportError:
            logger.error("reportlab not installed — PDF skipped")
            return

        ctx = self._context()

        # ── Palette — matches the HTML report's letterhead/document redesign ──
        NAVY    = colors.HexColor("#1F3864")
        BLUE    = colors.HexColor("#2E75B6")
        INK     = colors.HexColor("#1C2733")
        INK2    = colors.HexColor("#5B6B7F")
        INK3    = colors.HexColor("#8C98A6")
        WASH    = colors.HexColor("#F7F8FA")
        LINE    = colors.HexColor("#E1E5EA")
        CRIT    = colors.HexColor("#C00000")
        HIGH    = colors.HexColor("#E74C3C")
        HIGH_D  = colors.HexColor("#D35400")  # darker orange used in the donut (matches HTML conic-gradient)
        MED     = colors.HexColor("#B7950B")
        LOW_C   = colors.HexColor("#2E75B6")
        GREEN   = colors.HexColor("#1E8449")
        NONE_C  = colors.HexColor("#8C98A6")

        SEV_C = {"Critical": CRIT, "High": HIGH, "Medium": MED, "Low": LOW_C, "None": NONE_C}
        RISK_C = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": LOW_C, "INFORMATIONAL": GREEN}

        def _footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(INK3)
            canvas.drawString(2*cm, 1.3*cm,
                f"CyberScan Pro  ·  FUPRE Final Year Project  ·  Obeh Emmanuel Onoriode (COS/9581/2022)")
            canvas.drawRightString(A4[0]-2*cm, 1.3*cm, f"Page {doc_.page}")
            canvas.setStrokeColor(LINE)
            canvas.line(2*cm, 1.6*cm, A4[0]-2*cm, 1.6*cm)
            canvas.restoreState()

        doc = SimpleDocTemplate(path, pagesize=A4,
            topMargin=0, bottomMargin=2.2*cm,
            leftMargin=2*cm, rightMargin=2*cm,
            title="CyberScan Pro Report", author="Obeh Emmanuel Onoriode")

        SANS, SERIF = "Helvetica", "Times-Roman"
        SANS_B, SERIF_B = "Helvetica-Bold", "Times-Bold"

        def S(name, **kw):
            kw.setdefault("fontName", SANS)
            return ParagraphStyle(name, **kw)

        TITLE = S("T",  fontSize=22, textColor=colors.white, fontName=SERIF_B, leading=26)
        SUB   = S("SB", fontSize=8.5, textColor=colors.HexColor("#A8BEDD"), leading=12)
        LOGON = S("LN", fontSize=9,  textColor=colors.white, fontName=SANS_B, leading=11)
        MLB   = S("MLB",fontSize=6.5,textColor=colors.HexColor("#8DA3C9"), fontName=SANS_B, leading=9)
        MVAL  = S("MV", fontSize=10.5, textColor=colors.white, fontName=SANS_B, leading=13)

        H1    = S("H1", fontSize=14, textColor=NAVY, fontName=SERIF_B, spaceBefore=4, spaceAfter=8, leading=17)
        SECN  = S("SN", fontSize=7.5, textColor=INK3, fontName=SANS_B, leading=10)
        BD    = S("BD", fontSize=9,  leading=14, spaceAfter=6, textColor=INK, alignment=TA_JUSTIFY)
        SM    = S("SM", fontSize=7.5, textColor=INK3, leading=11)
        LB    = S("LB", fontSize=7.8,  textColor=INK2, fontName=SANS_B)
        PE    = S("PE", fontSize=8.5, leading=13, spaceAfter=3, textColor=INK2)
        TC    = S("TC", fontSize=8,  leading=11.5, textColor=INK2)
        TCB   = S("TCB",fontSize=8,  leading=11.5, fontName=SANS_B, textColor=colors.white)   # for header ROWS on navy backgrounds
        TCD   = S("TCD",fontSize=8,  leading=11.5, fontName=SANS_B, textColor=INK)            # for row LABELS on white backgrounds

        def sp(h=0.3): return Spacer(1, h*cm)
        def hr(): return HRFlowable(width="100%", thickness=0.75, color=LINE)
        def cell(txt, style=TC): return Paragraph(esc(txt), style)
        def esc(txt):
            return _html.escape(str(txt), quote=False)

        def donut(counts, total, size=3.0*cm):
            """Severity breakdown donut — mirrors the HTML report's conic-gradient chart."""
            d = Drawing(size, size)
            cx = cy = size / 2
            r = size / 2
            segs = [(counts.get("Critical", 0), CRIT), (counts.get("High", 0), HIGH_D),
                    (counts.get("Medium", 0), MED), (counts.get("Low", 0), LOW_C)]
            start = 90.0
            for n, col in segs:
                if n <= 0 or total <= 0:
                    continue
                angle = (n / total) * 360.0
                end = start - angle
                d.add(Wedge(cx, cy, r, end, start, fillColor=col, strokeColor=colors.white, strokeWidth=1.2))
                start = end
            d.add(Circle(cx, cy, r * 0.6, fillColor=colors.white, strokeColor=None))
            d.add(String(cx, cy + 1.5, str(total), fontSize=15, fontName=SERIF_B, fillColor=NAVY, textAnchor="middle"))
            d.add(String(cx, cy - 10, "FINDINGS", fontSize=4.8, fontName=SANS_B, fillColor=INK3, textAnchor="middle"))
            return d

        story = []

        # ── LETTERHEAD (one continuous navy block, matches the HTML cover band) ──
        risk     = ctx["risk_rating"]
        risk_col = RISK_C.get(risk, NONE_C)
        counts   = ctx["severity_counts"]

        logo_path = os.path.join(os.path.dirname(OUTPUT_DIR), "static", "logo.jpeg")
        logo_cell = ""
        if os.path.exists(logo_path):
            try:
                logo_cell = RLImage(logo_path, width=0.9*cm, height=0.9*cm)
            except Exception:
                logo_cell = ""

        logo_row = [logo_cell, Paragraph("CYBERSCAN PRO", LOGON)] if logo_cell else [Paragraph("CYBERSCAN PRO", LOGON)]
        logo_widths = [1.1*cm, 15.9*cm] if logo_cell else [17*cm]
        logo_table = Table([logo_row], colWidths=logo_widths)
        logo_table.setStyle(TableStyle([
            ("VALIGN", (0,0),(-1,-1), "MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),0), ("TOPPADDING",(0,0),(-1,-1),0), ("BOTTOMPADDING",(0,0),(-1,-1),0),
        ]))

        risk_chip = Table([[Paragraph(risk, S("RC", fontSize=9.5, textColor=colors.white, fontName=SANS_B, alignment=TA_CENTER))]], colWidths=[2.6*cm])
        risk_chip.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1), risk_col), ("TOPPADDING",(0,0),(-1,-1),5), ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ]))

        meta = Table([
            [Paragraph("TARGET", MLB), Paragraph("GENERATED", MLB), Paragraph("OVERALL RISK", MLB)],
            [Paragraph(esc(ctx["target"]), MVAL), Paragraph(ctx["generated_at"], MVAL), risk_chip],
            [sp(0.25), sp(0.25), sp(0.25)],
            [Paragraph("HOSTS DISCOVERED", MLB), Paragraph("TOTAL FINDINGS", MLB), Paragraph("SESSION ID", MLB)],
            [Paragraph(str(ctx["total_hosts"]), MVAL), Paragraph(str(ctx["total_findings"]), MVAL),
             Paragraph(esc(ctx["session_id"])[:12] + "...", S("SID", fontSize=9, textColor=colors.white, fontName="Courier"))],
        ], colWidths=[5.67*cm, 5.67*cm, 5.66*cm])
        meta.setStyle(TableStyle([
            ("TOPPADDING",(0,0),(-1,-1),1), ("BOTTOMPADDING",(0,0),(-1,-1),1), ("LEFTPADDING",(0,0),(-1,-1),0),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))

        letterhead = Table([
            [logo_table],
            [sp(0.45)],
            [Paragraph("Vulnerability Assessment Report", TITLE)],
            [Paragraph("AUTOMATED SECURITY ASSESSMENT  ·  FUPRE FINAL YEAR PROJECT  ·  OBEH EMMANUEL ONORIODE", SUB)],
            [sp(0.55)],
            [HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#3A5281"))],
            [sp(0.4)],
            [meta],
        ], colWidths=[17*cm])
        letterhead.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), NAVY),
            ("LEFTPADDING",   (0,0),(-1,-1), 16),
            ("RIGHTPADDING",  (0,0),(-1,-1), 16),
            ("TOPPADDING",    (0,0),(-1,-1), 0),
            ("BOTTOMPADDING", (0,0),(-1,-1), 0),
        ]))
        letterhead_wrap = Table([[letterhead]], colWidths=[17*cm])
        letterhead_wrap.setStyle(TableStyle([
            ("TOPPADDING",(0,0),(-1,-1), 22), ("BOTTOMPADDING",(0,0),(-1,-1), 22),
            ("LEFTPADDING",(0,0),(-1,-1), 0), ("RIGHTPADDING",(0,0),(-1,-1), 0),
        ]))

        story += [letterhead_wrap]

        # ── TARGET SCREENSHOT ──────────────────────────────────────────────
        screenshot_path = os.path.join(OUTPUT_DIR, "screenshots", f"screenshot_{self.session_id}.png")
        if os.path.exists(screenshot_path):
            try:
                from PIL import Image as PILImage
                with PILImage.open(screenshot_path) as im:
                    iw, ih = im.size
                max_w = 17 * cm
                display_h = min(max_w * (ih / iw), 8.5*cm)
                display_w = display_h * (iw/ih) if display_h == 8.5*cm else max_w
                story += [
                    RLImage(screenshot_path, width=display_w, height=display_h),
                    Paragraph(f"Figure 1 — Visual capture of {esc(ctx['target'])} at the time of this assessment.",
                              S("CAP", fontSize=7.5, textColor=INK3, fontName="Times-Italic", spaceBefore=4)),
                    sp(0.3),
                ]
            except Exception as e:
                logger.warning(f"Could not embed screenshot in PDF: {e}")

        story.append(PageBreak())

        # ── PLAIN ENGLISH GUIDE ────────────────────────────────────────────
        story += [Paragraph("What This Report Means", H1), hr(), sp(0.2),
                  Paragraph("This report was generated by CyberScan Pro after scanning <b>" + esc(ctx['target']) + "</b>. It identifies security weaknesses that could be exploited by attackers. <b>You do not need to be a technical expert to understand this report.</b> Every finding includes a plain English explanation of what the problem is, what could happen if exploited, and exactly how to fix it.", BD), sp(0.2)]

        guide = Table([
            [cell("CRITICAL", S("GH", fontSize=8, fontName=SANS_B, textColor=CRIT)),
             cell("HIGH", S("GH2", fontSize=8, fontName=SANS_B, textColor=HIGH)),
             cell("MEDIUM", S("GH3", fontSize=8, fontName=SANS_B, textColor=MED)),
             cell("LOW", S("GH4", fontSize=8, fontName=SANS_B, textColor=LOW_C))],
            [cell("Fix within 24 hours", SM), cell("Fix within 7 days", SM), cell("Fix within 30 days", SM), cell("Fix when possible", SM)],
            [cell("Attackers can fully compromise the system or steal all data", TC),
             cell("Significant damage or data breach likely", TC),
             cell("Moderate risk, specific conditions required to exploit", TC),
             cell("Minor risk, limited direct impact", TC)]
        ], colWidths=[4.25*cm]*4)
        guide.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), colors.white),
            ("GRID",          (0,0),(-1,-1), 0.6, LINE),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story += [guide, sp(0.35)]

        # ── EXECUTIVE SUMMARY (with donut chart) ────────────────────────────
        story += [Paragraph("Executive Summary", H1), hr(), sp(0.25)]

        total = ctx["total_findings"]
        if total > 0:
            legend_rows = []
            for name, col in [("Critical", CRIT), ("High", HIGH_D), ("Medium", MED), ("Low", LOW_C)]:
                swatch = Table([[""]], colWidths=[0.3*cm], rowHeights=[0.3*cm])
                swatch.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1), col)]))
                legend_rows.append([swatch, Paragraph(name, S("LGN", fontSize=9, textColor=INK)),
                                     Paragraph(str(counts.get(name,0)), S("LGV", fontSize=9, fontName=SANS_B, textColor=INK, alignment=2))])
            legend = Table(legend_rows, colWidths=[0.6*cm, 2.6*cm, 1*cm])
            legend.setStyle(TableStyle([
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("TOPPADDING",(0,0),(-1,-1),3), ("BOTTOMPADDING",(0,0),(-1,-1),3),
            ]))
            donut_row = Table([[donut(counts, total), legend]], colWidths=[3.4*cm, 4.3*cm])
            donut_row.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),0)]))
            story += [donut_row, sp(0.3)]

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
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, WASH]),
            ("GRID",          (0,0),(-1,-1), 0.5, LINE),
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
                host_block = [Paragraph(f"<font face='Courier-Bold'>{esc(host['ip'])}</font> — {esc(host.get('hostname','N/A'))} — OS: {esc(host.get('os','Unknown'))}",
                                         S("HT", fontSize=10.5, textColor=NAVY, fontName=SANS_B, spaceBefore=10, spaceAfter=6))]
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
                        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, WASH]),
                        ("GRID",          (0,0),(-1,-1), 0.5, LINE),
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
                              S("FH", fontSize=10.5, textColor=INK, fontName=SANS_B)),
                    Paragraph(sev, S("SV", fontSize=8.5, textColor=colors.white,
                                     fontName=SANS_B, alignment=1))
                ]], colWidths=[14*cm, 3*cm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(0,-1), WASH),
                    ("BACKGROUND",    (1,0),(1,-1), sc),
                    ("TOPPADDING",    (0,0),(-1,-1), 8),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 8),
                    ("LEFTPADDING",   (0,0),(0,-1), 10),
                    ("LINEBEFORE",    (0,0),(0,-1), 2.5, sc),
                ]))
                block.append(hdr)

                pe = Table([
                    [Paragraph("WHAT IS THIS VULNERABILITY?", LB),
                     Paragraph(f"WHAT DOES IT MEAN FOR {esc(ctx['target']).upper()}?", LB)],
                    [Paragraph(f.get("plain_what",""), PE),
                     Paragraph(f.get("plain_means",""), PE)],
                    [Paragraph("WHAT COULD AN ATTACKER DO?", LB),
                     Paragraph("HOW TO FIX IT", LB)],
                    [Paragraph(f.get("plain_impact",""), PE),
                     Paragraph(f.get("plain_fix","") + (f"<br/><br/><b>Difficulty:</b> {f.get('plain_difficulty','')}" if f.get("plain_difficulty") else ""), PE)],
                ], colWidths=[8.5*cm, 8.5*cm])
                pe.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), colors.white),
                    ("GRID",          (0,0),(-1,-1), 0.5, LINE),
                    ("TOPPADDING",    (0,0),(-1,-1), 7),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 7),
                    ("LEFTPADDING",   (0,0),(-1,-1), 9),
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ]))
                block.append(pe)

                td = Table([
                    [Paragraph("TECHNICAL DETAILS", LB), ""],
                    [cell("URL:", TCD),       cell(str(f.get("url",""))[:90])],
                    [cell("Evidence:", TCD), cell(str(f.get("evidence","N/A"))[:90])],
                ], colWidths=[3*cm, 14*cm])
                td.setStyle(TableStyle([
                    ("GRID",          (0,1),(-1,-1), 0.4, LINE),
                    ("TOPPADDING",    (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 5),
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
                      Paragraph("Automated attack tools scan for these vulnerabilities around the clock. Update the affected software immediately.", S("W", fontSize=9, textColor=CRIT, fontName=SANS_B, spaceBefore=6, spaceAfter=10)), sp(0.15)]

            cve_data = [[cell("CVE ID",TCB), cell("Host",TCB), cell("Port",TCB), cell("Service",TCB), cell("CVSS",TCB), cell("Severity",TCB)]]
            for f in ctx["cve_findings"]:
                cve_data.append([cell(f.get("cve_id","")), cell(f.get("host_ip","")),
                                  cell(str(f.get("port",""))), cell(str(f.get("service",""))[:20]),
                                  cell(str(f.get("cvss_score",""))), cell(f.get("severity",""))])
            ct = Table(cve_data, colWidths=[3.5*cm,3*cm,1.5*cm,3.5*cm,1.5*cm,4*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), NAVY),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, WASH]),
                ("GRID",          (0,0),(-1,-1), 0.5, LINE),
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
                              S("CH", fontSize=10, textColor=sc, fontName=SERIF_B, spaceBefore=8, spaceAfter=4)),
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
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, WASH]),
                ("GRID",          (0,0),(-1,-1), 0.5, LINE),
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
