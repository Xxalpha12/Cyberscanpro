"""
CyberScan Pro - Web Dashboard (Flask)
Full featured dashboard with auth, CSV export, comparison,
risk scoring, scheduling, email delivery, and more.
"""

from flask import (Flask, render_template, request, jsonify,
                   send_file, abort, redirect, url_for, session,
                   make_response)
import os
import io
import csv
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime, timedelta
from modules.database import Database
from modules.logger import get_logger
from modules.risk_scorer import score_all_hosts
from auth import auth, login_required
from flask import send_from_directory

logger = get_logger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cyberscanpro-secret-2025-change-me")
app.register_blueprint(auth)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
PORT = int(os.environ.get("PORT", 5000))
os.makedirs(OUTPUT_DIR, exist_ok=True)

active_scans = {}


# ── ROUTES ───────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    db = Database()
    db.fix_stale_sessions()
    sessions      = db.get_all_sessions()
    sev_counts    = db.get_severity_counts()
    total_findings = db.get_total_findings()

    # Enrich sessions with severity counts
    enriched = []
    for s in sessions:
        sc = db.get_severity_counts(s["id"])
        enriched.append({**dict(s), "severity_counts": sc})

    # Stats
    total_scans     = len(sessions)
    completed_scans = len([s for s in sessions if s["status"] == "completed"])
    failed_scans    = len([s for s in sessions if s["status"] == "error"])
    success_rate    = round(completed_scans / total_scans * 100) if total_scans else 0

    # Unique targets
    unique_targets  = len(set(s["target"] for s in sessions))

    # Security score calculation
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    med  = sev_counts.get("Medium", 0)
    low  = sev_counts.get("Low", 0)
    penalty = crit*25 + high*10 + med*5 + low*2
    security_score = max(0, min(100, 100 - penalty))
    security_score_last_week = max(0, security_score - 5)  # Simulated trend

    risk_rating = "CRITICAL" if crit > 0 else                   "HIGH"     if high > 0  else                   "MEDIUM"   if med > 0   else                   "LOW"      if low > 0   else "GOOD"

    # Vulnerability breakdown by type
    all_web = []
    for s in sessions:
        all_web.extend(db.get_web_findings(s["id"]))

    vuln_counts = {}
    for f in all_web:
        vt = f.get("vuln_type", "")
        vuln_counts[vt] = vuln_counts.get(vt, 0) + 1

    vuln_colors = {
        "SQL Injection": "#ef4444",
        "Cross-Site Scripting (XSS)": "#f97316",
        "Missing CSRF Protection": "#eab308",
        "Directory Traversal": "#a855f7",
        "Open Redirect": "#06b6d4",
    }
    vuln_types = []
    max_count  = max(vuln_counts.values()) if vuln_counts else 1
    for name, count in sorted(vuln_counts.items(), key=lambda x: -x[1])[:6]:
        short = name.replace("Missing Security Header: ", "").replace("Cross-Site Scripting", "XSS")
        vuln_types.append({
            "name":  short[:25],
            "count": count,
            "pct":   round(count / max_count * 100),
            "color": vuln_colors.get(name, "#3b82f6")
        })

    # Risk trend data for SVG chart
    completed = [s for s in sessions if s["status"] == "completed"][-6:]
    trend_labels = []
    trend_points = []
    if completed:
        scores = []
        for s in completed:
            sc = db.get_severity_counts(s["id"])
            p  = sc.get("Critical",0)*25 + sc.get("High",0)*10 + sc.get("Medium",0)*5 + sc.get("Low",0)*2
            scores.append(max(0, min(100, 100-p)))
            trend_labels.append((s.get("started_at","")[:10] or "")[-5:])

        if scores:
            min_s, max_s = min(scores), max(scores)
            rng = max_s - min_s if max_s != min_s else 1
            n   = len(scores)
            pts = []
            for i, sc in enumerate(scores):
                x = int(i / (n-1) * 380 + 10) if n > 1 else 200
                y = int(110 - ((sc - min_s) / rng * 90 + 10)) if rng else 60
                pts.append({"x": x, "y": y, "val": sc})
            trend_points = pts
            line_d  = "M " + " L ".join(f"{p['x']},{p['y']}" for p in pts)
            area_d  = line_d + f" L {pts[-1]['x']},120 L {pts[0]['x']},120 Z"
    else:
        line_d = area_d = ""

    # Activity feed from recent sessions
    activity_feed = []
    for s in enriched[:8]:
        sc     = s.get("severity_counts", {})
        t      = (s.get("started_at","")[:16] or "").replace("T"," ")
        status = s["status"]
        if status == "completed":
            crit_f = sc.get("Critical",0)
            if crit_f > 0:
                activity_feed.append({"type":"crit","message":f"Critical finding on {s['target']}","time":t,"badge":"CRITICAL","badge_type":"crit"})
            else:
                activity_feed.append({"type":"ok","message":f"Scan completed: {s['target']}","time":t,"badge":"Done","badge_type":"ok"})
        elif status == "error":
            activity_feed.append({"type":"warn","message":f"Scan failed: {s['target']}","time":t,"badge":None,"badge_type":""})
        else:
            activity_feed.append({"type":"scan","message":f"Scanning: {s['target']}","time":t,"badge":None,"badge_type":""})

    # Compliance scores (estimated from findings)
    base = max(0, 100 - penalty//2)
    owasp_score = min(100, base + 10)
    pci_score   = min(100, base - 5)
    iso_score   = min(100, base + 2)
    nist_score  = min(100, base - 8)

    # Recent reports
    import glob as gl
    output_dir   = os.path.join(os.path.dirname(__file__), "output")
    report_files = []
    if os.path.exists(output_dir):
        for f in sorted(os.listdir(output_dir), reverse=True):
            if f.endswith((".pdf",".html")) and "report" in f:
                parts = f.replace("cyberscanpro_report_","").split("_")
                sid   = parts[0] if parts else ""
                tgt   = next((s["target"] for s in sessions if s["id"] == sid), sid[:8])
                report_files.append({
                    "filename": f,
                    "type":     "pdf" if f.endswith(".pdf") else "html",
                    "target":   tgt,
                    "date":     f[f.rfind("_")-8:f.rfind("_")] if "_" in f else ""
                })
    recent_reports = report_files[:4]

    # Top targets
    target_map = {}
    for s in enriched:
        tgt = s["target"]
        if tgt not in target_map:
            target_map[tgt] = {"name":tgt,"scan_count":0,"latest_risk":"NONE"}
        target_map[tgt]["scan_count"] += 1
        sc = s.get("severity_counts",{})
        risk = "CRITICAL" if sc.get("Critical",0) > 0 else                "HIGH"     if sc.get("High",0) > 0     else                "MEDIUM"   if sc.get("Medium",0) > 0   else                "LOW"      if sc.get("Low",0) > 0       else "NONE"
        target_map[tgt]["latest_risk"] = risk
    top_targets = list(target_map.values())[:5]

    db.close()

    return render_template("dashboard.html",
        sessions=enriched,
        severity_counts=sev_counts,
        total_findings=total_findings,
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        success_rate=success_rate,
        unique_targets=unique_targets,
        security_score=security_score,
        security_score_last_week=security_score_last_week,
        risk_rating=risk_rating,
        vuln_types=vuln_types,
        trend_points=trend_points,
        trend_labels=trend_labels,
        trend_line=line_d if "line_d" in dir() else "",
        trend_area=area_d if "area_d" in dir() else "",
        activity_feed=activity_feed,
        owasp_score=owasp_score,
        pci_score=pci_score,
        iso_score=iso_score,
        nist_score=nist_score,
        recent_reports=recent_reports,
        top_targets=top_targets,
        page="home", title="Dashboard"
    )


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico", mimetype="image/vnd.microsoft.icon"
    )


@app.route("/scan/new", methods=["GET"])
@login_required
def new_scan():
    return render_template("new_scan.html", page="new_scan", title="New Scan")


@app.route("/scan/run", methods=["POST"])
@login_required
def run_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP or CIDR is required."}), 400

    # ── Duplicate scan guard ──────────────────────────────────────────────────
    # Prevent launching a second scan against the same target if one is running
    for sid, scan in active_scans.items():
        if scan.get("target") == target and scan.get("status") == "running":
            return jsonify({
                "error": f"A scan against '{target}' is already running (session {sid}). "
                         "Wait for it to finish or check the dashboard."
            }), 409

    from modules.network_scanner import NetworkScanner
    from modules.web_scanner import WebScanner
    from modules.web_tester import WebTester
    from modules.cve_scanner import CVEScanner
    from modules.report_generator import ReportGenerator

    db = Database()
    session_id = db.create_session(target)
    db.close()

    active_scans[session_id] = {
        "status": "running", "log": [], "target": target,
        "report_paths": [], "progress": 0,
        "hosts_found": 0, "web_count": 0, "cve_count": 0
    }

    def _log(msg):
        entry = f"[{_ts()}] {msg}"
        active_scans[session_id]["log"].append(entry)
        # Also persist to DB so it survives server restarts
        try:
            _db = Database()
            _db.append_log(session_id, entry)
            _db.close()
        except Exception:
            pass

    def _set_progress(pct, msg=None):
        active_scans[session_id]["progress"] = pct
        # Persist status to DB
        try:
            _db = Database()
            _db.set_scan_status(
                session_id, "running", pct,
                active_scans[session_id].get("hosts_found", 0),
                active_scans[session_id].get("web_count", 0),
                active_scans[session_id].get("cve_count", 0)
            )
            _db.close()
        except Exception:
            pass
        if msg:
            _log(msg)

    def _run():
        try:
            db = Database()
            _log(f"Scan started for target: {target}")
            _set_progress(3)

            # ── Network scan with live progress callback ──────────────────────
            _log("Running Network Scanner...")

            def net_progress(pct, msg):
                # Maps scanner's 5–30% range into our 5–28% range
                mapped = 5 + int(pct * 0.46)
                active_scans[session_id]["progress"] = min(mapped, 28)
                _log(msg)

            scanner = NetworkScanner(
                target=target,
                port_range=data.get("port_range", "1-1024"),
                scan_type=data.get("scan_type", "quick"),
                progress_callback=net_progress
            )
            hosts = scanner.run()
            db.save_hosts(session_id, hosts)
            active_scans[session_id]["hosts_found"] = len(hosts)
            _set_progress(30, f"Network scan complete — {len(hosts)} host(s), "
                              f"{sum(len(h.get('ports',[])) for h in hosts)} open port(s) total.")

            if not hosts:
                _log("WARNING: No hosts found. Check target, DNS, and network connectivity.")

            # ── Web + CVE in parallel ─────────────────────────────────────────
            _log("Launching Web Scanner + CVE Scanner simultaneously...")
            web_findings = []
            cve_findings = []

            def run_web():
                try:
                    _log("Web Scanner: checking security headers...")
                    header_scanner = WebScanner(hosts=hosts)
                    header_results = header_scanner.run()
                    _log(f"Web Scanner: {len(header_results)} header issue(s). Starting vuln tests...")

                    vuln_tester = WebTester(hosts=hosts)
                    vuln_results = vuln_tester.run()
                    combined = header_results + vuln_results
                    web_findings.extend(combined)

                    # Incremental save so dashboard counts update live
                    if combined:
                        db2 = Database()
                        db2.save_web_findings(session_id, combined)
                        db2.close()

                    active_scans[session_id]["web_count"] = len(combined)
                    _log(f"Web scan done — Headers: {len(header_results)} | Vulns: {len(vuln_results)}")

                    # Capture screenshot of target
                    try:
                        from modules.screenshot import ScreenshotCapture
                        sc = ScreenshotCapture()
                        sc_url = target if target.startswith("http") else f"http://{target}"
                        sc_path = sc.capture(sc_url, session_id)
                        if sc_path:
                            _log(f"Screenshot captured: {os.path.basename(sc_path)}")
                        else:
                            _log("Screenshot: target preview generated")
                    except Exception as e:
                        _log(f"Screenshot skipped: {e}")
                except Exception as e:
                    _log(f"Web scan error: {e}")

            def run_cve():
                try:
                    _log("CVE Scanner: mapping services to known CVEs...")
                    cve_scanner = CVEScanner(hosts=hosts)
                    results = cve_scanner.run()
                    cve_findings.extend(results)

                    # Incremental save
                    if results:
                        db3 = Database()
                        db3.save_cve_findings(session_id, results)
                        db3.close()

                    active_scans[session_id]["cve_count"] = len(results)
                    _log(f"CVE scan done — {len(results)} finding(s).")
                except Exception as e:
                    _log(f"CVE scan error: {e}")

            _set_progress(32)
            web_thread = threading.Thread(target=run_web, daemon=True)
            cve_thread = threading.Thread(target=run_cve, daemon=True)
            web_thread.start()
            cve_thread.start()

            # Update progress while threads run
            import time
            for pct in range(33, 74, 3):
                if not web_thread.is_alive() and not cve_thread.is_alive():
                    break
                time.sleep(1.5)
                active_scans[session_id]["progress"] = pct

            web_thread.join()
            cve_thread.join()

            _set_progress(75, f"All scans done — Web: {len(web_findings)} | CVE: {len(cve_findings)}")

            # Findings already saved incrementally inside run_web() and run_cve()
            # No double-save needed

            # ── Report ────────────────────────────────────────────────────────
            _set_progress(80, "Generating report...")
            gen = ReportGenerator(
                session_id=session_id, target=target,
                hosts=hosts, web_findings=web_findings,
                cve_findings=cve_findings,
                output_format=data.get("output_format", "both")
            )
            paths = gen.generate()
            active_scans[session_id]["report_paths"] = paths
            db.complete_session(session_id)

            if data.get("email"):
                _send_report_email(data["email"], target, session_id, paths)
                _log(f"Report emailed to {data['email']}")

            db.close()
            for p in paths:
                _log(f"Report saved: {os.path.basename(p)}")

            active_scans[session_id]["status"]   = "completed"
            active_scans[session_id]["progress"] = 100
            _log("Scan completed successfully.")
            try:
                _db = Database()
                _db.set_scan_status(session_id, "completed", 100,
                    active_scans[session_id].get("hosts_found", 0),
                    active_scans[session_id].get("web_count", 0),
                    active_scans[session_id].get("cve_count", 0),
                    ",".join(os.path.basename(p) for p in active_scans[session_id].get("report_paths",[])))
                _db.close()
            except Exception:
                pass

        except Exception as e:
            active_scans[session_id]["status"]   = "error"
            active_scans[session_id]["progress"] = 0
            _log(f"ERROR: {str(e)}")
            logger.error(f"Scan error: {e}")
            try:
                _db = Database()
                _db.set_scan_status(session_id, "error", 0)
                _db.close()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"session_id": session_id, "status": "started"})


@app.route("/scan/<session_id>/status")
@login_required
def scan_status(session_id):
    # Try in-memory first (fastest)
    if session_id in active_scans:
        scan = active_scans[session_id]
        return jsonify({
            "status":       scan["status"],
            "log":          scan["log"],
            "progress":     scan.get("progress", 0),
            "report_paths": [os.path.basename(p) for p in scan.get("report_paths", [])],
            "hosts_found":  scan.get("hosts_found", 0),
            "web_count":    scan.get("web_count", 0),
            "cve_count":    scan.get("cve_count", 0),
        })

    # Fall back to DB (handles server restarts on Render free tier)
    db = Database()
    db_status = db.get_scan_status(session_id)
    db_logs   = db.get_logs(session_id)
    db.close()

    if db_status:
        return jsonify({
            "status":       db_status["status"],
            "log":          db_logs,
            "progress":     db_status["progress"],
            "report_paths": [p for p in db_status["report_paths"].split(",") if p],
            "hosts_found":  db_status["hosts_found"],
            "web_count":    db_status["web_count"],
            "cve_count":    db_status["cve_count"],
        })

    return jsonify({"status": "not_found", "log": [], "progress": 0})


@app.route("/scan/<session_id>")
@login_required
def view_scan(session_id):
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    hosts           = db.get_hosts(session_id)
    web_findings    = db.get_web_findings(session_id)
    cve_findings    = db.get_cve_findings(session_id)
    severity_counts = db.get_severity_counts(session_id)
    total_findings  = db.get_total_findings(session_id)
    db.close()

    # Risk scoring
    risk_scores = score_all_hosts(hosts, web_findings, cve_findings)

    # Get report files for this session
    import glob
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    report_files = []
    if os.path.exists(output_dir):
        for ext in ["html", "pdf"]:
            pattern = os.path.join(output_dir, f"cyberscanpro_report_{session_id}_*.{ext}")
            report_files += [os.path.basename(f) for f in glob.glob(pattern)]
        # Also check old naming convention
        for ext in ["html", "pdf"]:
            pattern = os.path.join(output_dir, f"*_{session_id}_*.{ext}")
            report_files += [os.path.basename(f) for f in glob.glob(pattern)
                           if os.path.basename(f) not in report_files]

    return render_template(
        "scan_detail.html",
        session=sess, hosts=hosts,
        web_findings=web_findings, cve_findings=cve_findings,
        severity_counts=severity_counts, total_findings=total_findings,
        risk_scores=risk_scores,
        report_files=report_files,
        page="results", title=f"Scan {session_id}"
    )


@app.route("/scan/<session_id>/delete", methods=["POST"])
@login_required
def delete_scan(session_id):
    db = Database()
    if not db.get_session(session_id):
        return jsonify({"error": "Not found"}), 404
    db.delete_session(session_id)
    db.close()
    return jsonify({"success": True})


@app.route("/report/<filename>")
@login_required
def download_report(filename):
    # Security: only allow safe filenames
    import re
    if not re.match(r'^[\w\-\.]+$', filename):
        abort(400)
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    filepath = os.path.join(output_dir, filename)
    if not os.path.exists(filepath):
        abort(404)
    # Open PDF in browser, download HTML
    if filename.endswith(".pdf"):
        return send_file(filepath, as_attachment=False,
                        mimetype="application/pdf")
    elif filename.endswith(".html"):
        return send_file(filepath, as_attachment=False,
                        mimetype="text/html")
    return send_file(filepath, as_attachment=True)


# ── EXPORT CSV ───────────────────────────────────────────

@app.route("/export/csv")
@login_required
def export_csv():
    """Export all scan sessions as a CSV file."""
    db = Database()
    sessions = db.get_all_sessions()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Session ID", "Target", "Started At", "Completed At", "Status"])
    for s in sessions:
        writer.writerow([s["id"], s["target"], s["started_at"],
                         s.get("completed_at", ""), s["status"]])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=cyberscanpro_sessions.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route("/export/<session_id>/csv")
@login_required
def export_session_csv(session_id):
    """Export all findings for a specific session as CSV."""
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    web = db.get_web_findings(session_id)
    cve = db.get_cve_findings(session_id)
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["=== WEB FINDINGS ==="])
    writer.writerow(["Host IP", "URL", "Vulnerability", "Severity", "Description", "Recommendation"])
    for f in web:
        writer.writerow([f["host_ip"], f["url"], f["vuln_type"],
                         f["severity"], f["description"], f["recommendation"]])

    writer.writerow([])
    writer.writerow(["=== CVE FINDINGS ==="])
    writer.writerow(["Host IP", "Port", "Service", "CVE ID", "CVSS Score", "Severity", "Reference"])
    for f in cve:
        writer.writerow([f["host_ip"], f["port"], f["service"],
                         f["cve_id"], f["cvss_score"], f["severity"], f["reference"]])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=cyberscanpro_{session_id}_findings.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


# ── SCAN COMPARISON ───────────────────────────────────────

@app.route("/compare")
@login_required
def compare():
    db = Database()
    sessions = db.get_all_sessions()
    db.close()
    return render_template("compare.html", sessions=sessions,
                           page="compare", title="Compare Scans")


@app.route("/api/compare")
@login_required
def api_compare():
    """Return comparison data for two sessions."""
    sid1 = request.args.get("s1")
    sid2 = request.args.get("s2")
    if not sid1 or not sid2:
        return jsonify({"error": "Two session IDs required"}), 400

    db = Database()
    def get_data(sid):
        s = db.get_session(sid)
        if not s:
            return None
        return {
            "session":        s,
            "severity_counts": db.get_severity_counts(sid),
            "total_findings": db.get_total_findings(sid),
            "host_count":     len(db.get_hosts(sid)),
            "web_count":      len(db.get_web_findings(sid)),
            "cve_count":      len(db.get_cve_findings(sid)),
        }

    data1 = get_data(sid1)
    data2 = get_data(sid2)
    db.close()

    if not data1 or not data2:
        return jsonify({"error": "Session not found"}), 404

    return jsonify({"session1": data1, "session2": data2})


# ── CVE TREND ─────────────────────────────────────────────

@app.route("/api/cve-trend")
@login_required
def api_cve_trend():
    """Return CVE finding counts per session for trend chart."""
    db = Database()
    sessions = db.get_all_sessions()
    trend = []
    for s in sessions[-10:]:  # Last 10 sessions
        counts = db.get_severity_counts(s["id"])
        trend.append({
            "session_id": s["id"],
            "target":     s["target"],
            "date":       s["started_at"][:10],
            "critical":   counts["Critical"],
            "high":       counts["High"],
            "medium":     counts["Medium"],
            "low":        counts["Low"],
            "total":      sum(counts.values())
        })
    db.close()
    return jsonify(trend)


# ── REMEDIATION CHECKLIST ─────────────────────────────────

@app.route("/scan/<session_id>/checklist")
@login_required
def remediation_checklist(session_id):
    """Generate a downloadable remediation checklist."""
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    web_findings = db.get_web_findings(session_id)
    cve_findings = db.get_cve_findings(session_id)
    db.close()
    return render_template("checklist.html",
                           session=sess,
                           web_findings=web_findings,
                           cve_findings=cve_findings)


# ── EMAIL DELIVERY ────────────────────────────────────────

def _send_report_email(recipient: str, target: str, session_id: str, report_paths: list):
    """
    Send scan report via email using SMTP.
    Set these in Render Environment Variables:
      SMTP_HOST = smtp.gmail.com
      SMTP_PORT = 587
      SMTP_USER = your Gmail address
      SMTP_PASS = your Gmail App Password
    Gmail App Password: Google Account → Security → 2-Step Verification → App Passwords
    """
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        logger.warning("Email not sent: Set SMTP_USER and SMTP_PASS in Render Environment Variables.")
        return

    logger.info(f"Sending report email to {recipient} via {smtp_host}:{smtp_port}")

    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = recipient
        msg["Subject"] = f"CyberScan Pro Report — {target} [{session_id}]"

        body = f"""CyberScan Pro — Automated Vulnerability Assessment Report

Target:     {target}
Session ID: {session_id}
Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please find the attached penetration test report.

---
CyberScan Pro | FUPRE Final Year Project | Obeh Emmanuel Onoriode
⚠ This report is confidential. Authorized use only.
"""
        msg.attach(MIMEText(body, "plain"))

        # Attach PDF report if available
        for path in report_paths:
            if path.endswith(".pdf") and os.path.exists(path):
                with open(path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition",
                                    f"attachment; filename={os.path.basename(path)}")
                    msg.attach(part)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipient, msg.as_string())

        logger.info(f"Report emailed to {recipient}")
    except Exception as e:
        logger.error(f"Email failed: {e}")


# ── API ───────────────────────────────────────────────────

@app.route("/api/sync", methods=["POST"])
def api_sync():
    """
    Receive scan data from local CyberScan Pro instance and store it.
    Called by local instance after completing a scan.
    Requires API_KEY env var to be set for security.
    """
    api_key = os.environ.get("SYNC_API_KEY", "")
    if api_key:
        provided = request.headers.get("X-API-Key", "")
        if provided != api_key:
            return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        db = Database()
        session_id = data.get("session_id")
        target     = data.get("target", "unknown")
        hosts      = data.get("hosts", [])
        web_findings = data.get("web_findings", [])
        cve_findings = data.get("cve_findings", [])

        # Create session if it doesn't exist
        existing = db.get_session(session_id)
        if not existing:
            db.conn.cursor().execute("""
                INSERT OR IGNORE INTO scan_sessions
                (id, target, status, started_at, completed_at)
                VALUES (?, ?, 'completed', ?, ?)
            """, (session_id, target,
                  data.get("started_at", datetime.now().isoformat()),
                  data.get("completed_at", datetime.now().isoformat())))
            db.conn.commit()

        db.save_hosts(session_id, hosts)
        db.save_web_findings(session_id, web_findings)
        db.save_cve_findings(session_id, cve_findings)
        db.complete_session(session_id)
        db.close()

        logger.info(f"Synced local scan: {session_id} target={target}")
        return jsonify({"success": True, "session_id": session_id})

    except Exception as e:
        logger.error(f"Sync error: {e}")
        return jsonify({"error": str(e)}), 500


# ── SCREENSHOT ROUTES ────────────────────────────────────────────────────────

@app.route("/screenshots/<session_id>")
@login_required
def get_screenshot(session_id):
    """Serve screenshot for a session."""
    import glob
    screenshot_dir = os.path.join(os.path.dirname(__file__), "output", "screenshots")
    pattern = os.path.join(screenshot_dir, f"screenshot_{session_id}.png")
    matches = glob.glob(pattern)
    if matches:
        return send_from_directory(screenshot_dir, f"screenshot_{session_id}.png")
    return jsonify({"error": "Screenshot not found"}), 404


@app.route("/api/screenshot/<session_id>", methods=["POST"])
@login_required
def capture_screenshot(session_id):
    """Trigger screenshot capture for a session."""
    from modules.screenshot import ScreenshotCapture
    db = Database()
    sess = db.get_session(session_id)
    hosts = db.get_hosts(session_id)
    db.close()

    if not sess:
        return jsonify({"error": "Session not found"}), 404

    target = sess["target"]
    if not target.startswith("http"):
        target = f"http://{target}"

    sc = ScreenshotCapture()
    path = sc.capture(target, session_id)

    if path:
        return jsonify({"success": True, "url": f"/screenshots/{session_id}"})
    return jsonify({"success": False, "error": "Screenshot capture failed"}), 500


# ── SCHEDULE ROUTES ──────────────────────────────────────────────────────────

@app.route("/schedules")
@login_required
def schedules():
    db = Database()
    scheds = db.get_all_schedules()
    db.close()
    return render_template("schedules.html", schedules=scheds,
                           page="schedules", title="Scan Schedules")


@app.route("/api/schedules", methods=["GET"])
@login_required
def api_get_schedules():
    db = Database()
    scheds = db.get_all_schedules()
    db.close()
    return jsonify(scheds)


@app.route("/api/schedules", methods=["POST"])
@login_required
def api_create_schedule():
    data      = request.get_json()
    target    = data.get("target","").strip()
    scan_type = data.get("scan_type","quick")
    port_range = data.get("port_range","1-1024")
    frequency = data.get("frequency","daily")

    if not target:
        return jsonify({"error": "Target required"}), 400

    freq_hours = {"hourly": 1, "daily": 24, "weekly": 168}
    hours      = freq_hours.get(frequency, 24)
    next_run   = (datetime.now() + timedelta(hours=hours)).isoformat()

    db = Database()
    sid = db.create_schedule(target, scan_type, port_range, frequency, next_run)
    db.close()
    return jsonify({"success": True, "id": sid, "next_run": next_run})


@app.route("/api/schedules/<int:schedule_id>", methods=["DELETE"])
@login_required
def api_delete_schedule(schedule_id):
    db = Database()
    db.delete_schedule(schedule_id)
    db.close()
    return jsonify({"success": True})


# ── SCAN HISTORY ──────────────────────────────────────────────────────────────

@app.route("/history")
@login_required
def history():
    db = Database()
    sessions = db.get_all_sessions()
    enriched = []
    total_findings = 0
    for s in sessions:
        counts   = db.get_severity_counts(s["id"])
        findings = db.get_total_findings(s["id"])
        total_findings += findings
        risk = "CRITICAL" if counts["Critical"] > 0 else                "HIGH"     if counts["High"] > 0     else                "MEDIUM"   if counts["Medium"] > 0   else                "LOW"      if counts["Low"] > 0       else "NONE"
        enriched.append({**dict(s),
            "severity_counts": counts,
            "risk_rating": risk})
    db.close()
    return render_template("history.html",
        sessions=enriched,
        total=len(sessions),
        completed=len([s for s in sessions if s["status"]=="completed"]),
        errors=len([s for s in sessions if s["status"]=="error"]),
        total_findings=total_findings,
        page="history", title="Scan History")


# ── NOTES ─────────────────────────────────────────────────────────────────────

@app.route("/api/notes/<session_id>", methods=["GET"])
@login_required
def get_notes(session_id):
    db = Database()
    notes = db.get_notes(session_id)
    db.close()
    return jsonify({"notes": notes})


@app.route("/api/notes/<session_id>", methods=["POST"])
@login_required
def save_notes(session_id):
    data  = request.get_json()
    notes = data.get("notes", "")
    db    = Database()
    db.save_notes(session_id, notes)
    db.close()
    return jsonify({"success": True})


# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────

@app.route("/api/risk-chart")
@login_required
def risk_chart_data():
    db = Database()
    sessions = [s for s in db.get_all_sessions()
                if s["status"] == "completed"][:10]
    chart_data = []
    for s in sessions:
        counts = db.get_severity_counts(s["id"])
        score  = min(counts["Critical"]*25 + counts["High"]*15 +
                     counts["Medium"]*8  + counts["Low"]*3, 100)
        chart_data.append({
            "target": s["target"][:25],
            "score":  score,
            "date":   s.get("started_at","")[:10]
        })
    db.close()
    return jsonify(chart_data)



# ── REPORTS PAGE ─────────────────────────────────────────────────────────────

@app.route("/reports")
@login_required
def reports_page():
    import glob, os
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)

    db = Database()
    sessions = db.get_all_sessions()
    db.close()

    # Build session lookup for risk ratings
    session_risks = {}
    session_targets = {}
    db2 = Database()
    for s in sessions:
        counts = db2.get_severity_counts(s["id"])
        risk = "CRITICAL" if counts["Critical"] > 0 else                "HIGH"     if counts["High"] > 0     else                "MEDIUM"   if counts["Medium"] > 0   else                "LOW"      if counts["Low"] > 0       else "NONE"
        session_risks[s["id"]]   = risk
        session_targets[s["id"]] = s["target"]
    db2.close()

    # Scan output directory for report files
    reports = []
    if os.path.exists(output_dir):
        for f in sorted(os.listdir(output_dir), reverse=True):
            if not (f.endswith(".pdf") or f.endswith(".html")):
                continue
            filepath = os.path.join(output_dir, f)
            size_kb  = os.path.getsize(filepath) // 1024

            # Extract session_id from filename
            parts = f.replace("cyberscanpro_report_","").replace("netscampro_report_","").split("_")
            session_id = parts[0] if parts else ""

            # Determine type
            if f.endswith(".pdf"):
                rtype = "pdf"
            elif "checklist" in f.lower():
                rtype = "checklist"
            else:
                rtype = "html"

            # Get date from filename or file mtime
            try:
                import datetime
                mtime = os.path.getmtime(filepath)
                date  = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            except:
                date = "Unknown"

            reports.append({
                "filename":   f,
                "type":       rtype,
                "target":     session_targets.get(session_id, session_id[:8] if session_id else "Unknown"),
                "session_id": session_id,
                "risk":       session_risks.get(session_id, "NONE"),
                "date":       date,
                "size":       f"{size_kb} KB",
            })

    pdf_count   = sum(1 for r in reports if r["type"] == "pdf")
    html_count  = sum(1 for r in reports if r["type"] == "html")
    sess_ids    = set(r["session_id"] for r in reports)

    return render_template("reports.html",
        reports=reports,
        total_reports=len(reports),
        pdf_count=pdf_count,
        html_count=html_count,
        sessions_with_reports=len(sess_ids),
        page="reports", title="Reports"
    )


@app.route("/api/report/<filename>/delete", methods=["POST"])
@login_required
def delete_report(filename):
    import re
    if not re.match(r"^[\w\-\.]+$", filename):
        return jsonify({"error": "Invalid filename"}), 400
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    filepath   = os.path.join(output_dir, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({"success": True})
    return jsonify({"error": "File not found"}), 404


# ── TARGETS PAGE ──────────────────────────────────────────────────────────────

@app.route("/targets")
@login_required
def targets_page():
    db = Database()
    sessions = db.get_all_sessions()

    # Group sessions by target
    target_map = {}
    for s in sessions:
        tgt = s["target"]
        if tgt not in target_map:
            target_map[tgt] = []
        target_map[tgt].append(s)

    targets = []
    for tgt, scans in target_map.items():
        # Get findings for each scan
        total_c = total_h = total_m = total_l = 0
        latest_risk = "NONE"
        latest_ip   = ""

        for s in scans:
            counts = db.get_severity_counts(s["id"])
            total_c += counts["Critical"]
            total_h += counts["High"]
            total_m += counts["Medium"]
            total_l += counts["Low"]

        # Latest scan risk
        if scans:
            latest = scans[0]
            counts = db.get_severity_counts(latest["id"])
            latest_risk = "CRITICAL" if counts["Critical"] > 0 else                           "HIGH"     if counts["High"] > 0     else                           "MEDIUM"   if counts["Medium"] > 0   else                           "LOW"      if counts["Low"] > 0       else "NONE"
            # Get IP from hosts
            hosts = db.get_hosts(latest["id"])
            if hosts:
                latest_ip = hosts[0].get("ip","")

        # Risk trend (compare last 2 scans)
        trend = "stable"
        if len(scans) >= 2:
            c1 = db.get_severity_counts(scans[0]["id"])
            c2 = db.get_severity_counts(scans[1]["id"])
            score1 = c1["Critical"]*25 + c1["High"]*10 + c1["Medium"]*5 + c1["Low"]*1
            score2 = c2["Critical"]*25 + c2["High"]*10 + c2["Medium"]*5 + c2["Low"]*1
            if score1 > score2:
                trend = "worse"
            elif score1 < score2:
                trend = "better"

        # Add total_findings to each scan
        enriched_scans = []
        for s in scans:
            total = db.get_total_findings(s["id"])
            enriched_scans.append({**dict(s), "total_findings": total})

        targets.append({
            "name":           tgt,
            "ip":             latest_ip,
            "scan_count":     len(scans),
            "latest_risk":    latest_risk,
            "total_critical": total_c,
            "total_high":     total_h,
            "total_medium":   total_m,
            "total_low":      total_l,
            "trend":          trend,
            "recent_scans":   enriched_scans[:5],
        })

    # Sort by latest risk severity
    risk_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"NONE":4}
    targets.sort(key=lambda x: risk_order.get(x["latest_risk"], 4))

    db.close()
    return render_template("targets.html",
        targets=targets,
        page="targets", title="Targets"
    )


# ── SETTINGS PAGE ─────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings_page():
    import shutil
    return render_template("settings.html",
        nmap_available    = bool(shutil.which("nmap")),
        use_postgres      = bool(os.environ.get("DATABASE_URL","")),
        nvd_key           = bool(os.environ.get("NVD_API_KEY","")),
        smtp_configured   = bool(os.environ.get("SMTP_USER","") and os.environ.get("SMTP_PASS","")),
        smtp_host         = os.environ.get("SMTP_HOST","smtp.gmail.com"),
        smtp_port         = os.environ.get("SMTP_PORT","587"),
        smtp_user         = os.environ.get("SMTP_USER",""),
        smtp_pass         = os.environ.get("SMTP_PASS",""),
        screenshot_key    = bool(os.environ.get("SCREENSHOT_API_KEY","")),
        sync_key          = bool(os.environ.get("SYNC_API_KEY","")),
        scan_threads      = os.environ.get("SCAN_THREADS","100"),
        max_cidr          = os.environ.get("MAX_CIDR_HOSTS","50"),
        scan_timeout      = os.environ.get("SCAN_TIMEOUT","1"),
        login_user        = os.environ.get("NETSCAN_USER","admin"),
        login_pass        = os.environ.get("NETSCAN_PASS","admin123"),
        page="settings", title="Settings"
    )


@app.route("/api/test-email", methods=["POST"])
@login_required
def test_email():
    data      = request.get_json()
    recipient = data.get("email","")
    if not recipient:
        return jsonify({"error": "No email provided"}), 400
    try:
        _send_report_email(recipient, "Test Target", "test-session-id", [])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ── NOTIFICATIONS API ─────────────────────────────────────────────────────────

@app.route("/api/notifications")
@login_required
def api_notifications():
    db     = Database()
    counts = db.get_severity_counts()
    db.close()
    notifs = []
    if counts["Critical"] > 0:
        notifs.append({"message": f"{counts['Critical']} Critical vulnerability(ies) found — immediate action required", "type": "critical"})
    if counts["High"] > 0:
        notifs.append({"message": f"{counts['High']} High severity finding(s) — address within 7 days", "type": "high"})
    return jsonify(notifs)


# ── ACTIVITY FEED API ─────────────────────────────────────────────────────────

@app.route("/api/activity-feed")
@login_required
def api_activity_feed():
    db       = Database()
    sessions = db.get_all_sessions()
    feed     = []
    for s in sessions[:10]:
        sc     = db.get_severity_counts(s["id"])
        t      = (s.get("started_at","")[:16] or "").replace("T"," ")
        status = s["status"]
        if status == "completed":
            if sc.get("Critical",0) > 0:
                feed.append({"type":"crit","message":f"Critical finding on {s['target']}","time":t,"badge":"CRITICAL","badge_type":"crit"})
            else:
                feed.append({"type":"ok","message":f"Scan completed: {s['target']}","time":t,"badge":"Done","badge_type":"ok"})
        elif status == "error":
            feed.append({"type":"warn","message":f"Scan failed: {s['target']}","time":t,"badge":"Failed","badge_type":"warn"})
        elif status == "running":
            feed.append({"type":"scan","message":f"Scanning in progress: {s['target']}","time":t,"badge":None,"badge_type":""})
    db.close()
    return jsonify(feed)


# ── SEVERITY COUNTS API ───────────────────────────────────────────────────────

@app.route("/api/severity-counts")
@login_required
def api_severity_counts():
    db     = Database()
    counts = db.get_severity_counts()
    db.close()
    return jsonify(counts)


# ── SESSIONS API ──────────────────────────────────────────────────────────────

@app.route("/api/sessions")
@login_required
def api_sessions():
    db       = Database()
    sessions = db.get_all_sessions()
    result   = []
    for s in sessions[:10]:
        sc = db.get_severity_counts(s["id"])
        result.append({
            "id":       s["id"],
            "target":   s["target"],
            "status":   s["status"],
            "started_at": s.get("started_at",""),
            "severity_counts": sc
        })
    db.close()
    return jsonify(result)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
