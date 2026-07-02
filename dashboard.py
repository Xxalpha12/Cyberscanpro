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
            n   = len(scores)
            pts = []
            for i, sc in enumerate(scores):
                pts.append({"x": i, "y": i, "val": sc})
            trend_points = pts
            line_d = ""
            area_d = ""
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
        recent_reports=[],
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


@app.route("/scan/start", methods=["POST"])
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

            # ── Persist report files into the database (survives Render redeploys) ──
            for p in paths:
                try:
                    with open(p, "rb") as fbytes:
                        file_bytes = fbytes.read()
                    fname = os.path.basename(p)
                    ftype = "pdf" if fname.endswith(".pdf") else "html"
                    db.save_report_file(session_id, target, fname, ftype, file_bytes)
                    _log(f"Report persisted to database: {fname}")
                except Exception as e:
                    _log(f"WARNING: Could not persist report {p}: {e}")

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


@app.route("/api/scan-status/<session_id>")
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

    # Risk scoring
    risk_scores = score_all_hosts(hosts, web_findings, cve_findings)

    # Get report files for this session — from the DATABASE (persistent across redeploys)
    db_reports = db.get_reports_for_session(session_id)
    report_files = [r["filename"] for r in db_reports]
    db.close()

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
    """Permanently delete a scan session and all its data — irreversible."""
    db = Database()
    if not db.get_session(session_id):
        db.close()
        return jsonify({"error": "Not found"}), 404
    db.delete_session_permanently(session_id)
    db.close()
    db.close()
    return jsonify({"success": True})


@app.route("/report/<filetype>/<session_id>")
@login_required
def download_report_by_session(filetype, session_id):
    """Serve the most recent report for a session, by type (pdf/html), from the database."""
    import re
    if not re.match(r'^[\w\-]+$', session_id):
        abort(400)
    db = Database()
    reports = db.get_reports_for_session(session_id)
    db.close()
    ext = "pdf" if filetype == "pdf" else "html"
    matches = [r for r in reports if r["file_type"] == ext]
    if not matches:
        abort(404)
    filename = matches[0]["filename"]
    return download_report(filename)


@app.route("/report/<filename>")
@login_required
def download_report(filename):
    import re
    if not re.match(r'^[\w\-\.]+$', filename):
        abort(400)

    db = Database()
    record = db.get_report_file(filename)
    db.close()

    if not record:
        # Fallback: try disk (covers reports generated before DB persistence was added)
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        filepath = os.path.join(output_dir, filename)
        if os.path.exists(filepath):
            mimetype = "application/pdf" if filename.endswith(".pdf") else "text/html"
            return send_file(filepath, as_attachment=False, mimetype=mimetype)
        abort(404)

    from io import BytesIO
    mimetype = "application/pdf" if record["file_type"] == "pdf" else "text/html"
    return send_file(
        BytesIO(record["file_data"]),
        as_attachment=False,
        mimetype=mimetype,
        download_name=filename
    )





def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ── NOTIFICATIONS API ─────────────────────────────────────────────────────────




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







@app.route("/api/test-email", methods=["POST"])
@login_required
def test_email():
    import smtplib
    from email.mime.text import MIMEText
    data  = request.get_json() or {}
    email = data.get("email","")
    if not email:
        return jsonify({"success": False, "error": "No email provided"})
    smtp_host = os.environ.get("SMTP_HOST","smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER","")
    smtp_pass = os.environ.get("SMTP_PASS","")
    if not smtp_user or not smtp_pass:
        return jsonify({"success": False, "error": "SMTP not configured"})
    try:
        msg = MIMEText("CyberScan Pro email test — SMTP is working correctly.")
        msg["Subject"] = "CyberScan Pro — Test Email"
        msg["From"]    = smtp_user
        msg["To"]      = email
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── COMPARE PAGE ──────────────────────────────────────────────────────────────

@app.route("/compare")
@login_required
def compare_page():
    db = Database()
    sessions = db.get_all_sessions()
    db.close()
    return render_template("history.html",
        sessions=sessions,
        page="compare", title="Compare Scans"
    )


# ── SCREENSHOTS API ───────────────────────────────────────────────────────────

@app.route("/api/screenshot/<session_id>", methods=["POST"])
@login_required
def capture_screenshot(session_id):
    db = Database()
    sess = db.get_session(session_id)
    db.close()
    if not sess:
        return jsonify({"success": False, "error": "Session not found"})
    target = sess["target"]
    api_key = os.environ.get("SCREENSHOT_API_KEY","")
    if not api_key:
        return jsonify({"success": False, "error": "Screenshot API key not configured"})
    try:
        import urllib.request
        url = f"https://api.screenshotone.com/take?access_key={api_key}&url=https://{target}&format=jpg&viewport_width=1280&viewport_height=800"
        screenshot_dir = os.path.join(os.path.dirname(__file__), "static", "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        save_path = os.path.join(screenshot_dir, f"{session_id}.jpg")
        urllib.request.urlretrieve(url, save_path)
        return jsonify({"success": True, "url": f"/screenshots/{session_id}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/screenshots/<session_id>")
@login_required
def serve_screenshot(session_id):
    import re
    if not re.match(r'^[\w\-]+$', session_id):
        abort(400)
    screenshot_dir = os.path.join(os.path.dirname(__file__), "static", "screenshots")
    path = os.path.join(screenshot_dir, f"{session_id}.jpg")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype="image/jpeg")


# ── NOTES API ─────────────────────────────────────────────────────────────────

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
    data  = request.get_json() or {}
    notes = data.get("notes","")
    db = Database()
    db.save_notes(session_id, notes)
    db.close()
    return jsonify({"success": True})



# ── LIVE CVE LOOKUP (NVD) ─────────────────────────────────────────────────────

@app.route("/api/live/cve/<cve_id>")
@login_required
def live_cve_lookup(cve_id):
    import urllib.request, json, re
    if not re.match(r"^CVE-\d{4}-\d+$", cve_id.upper()):
        return jsonify({"error": "Invalid CVE ID format"})
    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return jsonify({"error": "CVE not found in NVD"})
        cve = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d["lang"]=="en"), "No description")
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData",{})
                break
        return jsonify({
            "cve_id":      cve_id.upper(),
            "description": desc,
            "cvss_score":  cvss.get("baseScore") if cvss else "N/A",
            "severity":    cvss.get("baseSeverity") if cvss else "N/A",
            "published":   cve.get("published","")[:10],
            "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ── LIVE EXPLOIT-DB SEARCH ────────────────────────────────────────────────────

@app.route("/api/live/exploit/<query>")
@login_required
def live_exploit_search(query):
    import urllib.request, json, urllib.parse
    q = urllib.parse.quote(query[:50])
    url = f"https://exploit-db.com/search?q={q}&type=local&platform=&format=json"
    # ExploitDB doesn't have a free JSON API - use their search page scraping
    # Instead use a curated known-exploits list approach
    try:
        req = urllib.request.Request(
            f"https://cvedb.shodan.io/cve/{q}",
            headers={"User-Agent": "CyberScanPro/1.0"}
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        return jsonify({"results": [data] if data else [], "source": "Shodan CVE DB"})
    except Exception:
        # Fallback: return a helpful redirect
        return jsonify({
            "redirect": f"https://www.exploit-db.com/search?q={query}",
            "message": f"Search '{query}' on Exploit-DB",
            "results": []
        })


# ── LIVE IP REPUTATION (AbuseIPDB) ───────────────────────────────────────────

@app.route("/api/live/ip/<ip>")
@login_required
def live_ip_reputation(ip):
    import urllib.request, json, re
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"error": "Invalid IP address"})
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return jsonify({"error": "AbuseIPDB API key not configured", "setup": "Add ABUSEIPDB_API_KEY to Render environment variables. Free key at abuseipdb.com"})
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        d = data.get("data", {})
        return jsonify({
            "ip":              ip,
            "abuse_score":     d.get("abuseConfidenceScore", 0),
            "country":         d.get("countryCode","Unknown"),
            "isp":             d.get("isp","Unknown"),
            "total_reports":   d.get("totalReports", 0),
            "last_reported":   d.get("lastReportedAt","Never")[:10] if d.get("lastReportedAt") else "Never",
            "is_whitelisted":  d.get("isWhitelisted", False),
            "usage_type":      d.get("usageType","Unknown"),
            "domain":          d.get("domain",""),
        })
    except Exception as e:
        return jsonify({"error": str(e)})


# ── LIVE PORT INTELLIGENCE ────────────────────────────────────────────────────

@app.route("/api/live/port/<int:port>")
@login_required
def live_port_intel(port):
    PORT_DB = {
        21:   {"service":"FTP","risk":"HIGH","notes":"Unencrypted file transfer. Credentials sent in plaintext. Use SFTP instead.","cves":["CVE-2010-4221","CVE-2011-2523"]},
        22:   {"service":"SSH","risk":"MEDIUM","notes":"Secure remote access. Risk if using default credentials or weak ciphers. Disable root login.","cves":[]},
        23:   {"service":"Telnet","risk":"CRITICAL","notes":"Completely unencrypted. Never use on production. Replace with SSH immediately.","cves":["CVE-2020-10188"]},
        25:   {"service":"SMTP","risk":"MEDIUM","notes":"Email server. Risk of open relay abuse. Should require authentication.","cves":[]},
        53:   {"service":"DNS","risk":"MEDIUM","notes":"DNS server. Risk of DNS amplification attacks if open resolver.","cves":["CVE-2020-1350"]},
        80:   {"service":"HTTP","risk":"MEDIUM","notes":"Unencrypted web traffic. Should redirect to HTTPS (443). Exposes data in transit.","cves":[]},
        443:  {"service":"HTTPS","risk":"LOW","notes":"Encrypted web traffic. Check TLS version — TLS 1.0/1.1 are deprecated.","cves":[]},
        445:  {"service":"SMB","risk":"CRITICAL","notes":"Windows file sharing. Historically exploited (WannaCry, EternalBlue). Block externally.","cves":["CVE-2017-0144","CVE-2020-0796"]},
        1433: {"service":"MSSQL","risk":"HIGH","notes":"Microsoft SQL Server. Should never be exposed to the internet.","cves":[]},
        3306: {"service":"MySQL","risk":"HIGH","notes":"MySQL database. Must never be publicly accessible. Bind to localhost only.","cves":["CVE-2012-2122"]},
        3389: {"service":"RDP","risk":"HIGH","notes":"Windows Remote Desktop. Frequent brute-force target. Use VPN and NLA.","cves":["CVE-2019-0708"]},
        5432: {"service":"PostgreSQL","risk":"HIGH","notes":"PostgreSQL database. Must never be publicly accessible.","cves":[]},
        6379: {"service":"Redis","risk":"CRITICAL","notes":"Redis cache. Default has NO authentication. Trivially exploitable if exposed.","cves":["CVE-2022-0543"]},
        8080: {"service":"HTTP-Alt","risk":"MEDIUM","notes":"Alternative HTTP port. Often used by dev servers or proxies accidentally left open.","cves":[]},
        8443: {"service":"HTTPS-Alt","risk":"LOW","notes":"Alternative HTTPS port. Verify this is intentional and certificate is valid.","cves":[]},
        27017:{"service":"MongoDB","risk":"CRITICAL","notes":"MongoDB. Early versions had NO auth by default. Massive data breach risk.","cves":["CVE-2019-2389"]},
    }
    info = PORT_DB.get(port, {
        "service": f"Port {port}",
        "risk": "UNKNOWN",
        "notes": f"Port {port} is not in our intelligence database. Investigate manually to determine if this service should be exposed.",
        "cves": []
    })
    # Also check which of your scans found this port open
    db = Database()
    sessions = db.get_all_sessions()
    found_on = []
    for s in sessions:
        hosts = db.get_hosts(s["id"])
        for h in hosts:
            for p in h.get("ports",[]):
                if p.get("port") == port and p.get("state") == "open":
                    found_on.append({
                        "target": s["target"],
                        "session_id": s["id"],
                        "service": p.get("service",""),
                        "version": p.get("version",""),
                    })
    db.close()
    return jsonify({**info, "port": port, "found_on_your_targets": found_on[:5]})


# ── LIVE VIRUSTOTAL LOOKUP ────────────────────────────────────────────────────

@app.route("/api/live/vt/<path:target>")
@login_required
def live_virustotal(target):
    import urllib.request, json, hashlib
    api_key = os.environ.get("VIRUSTOTAL_API_KEY","")
    if not api_key:
        return jsonify({"error": "VirusTotal API key not configured", "setup": "Add VIRUSTOTAL_API_KEY to Render environment variables. Free at virustotal.com"})
    import re
    is_ip     = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
    is_domain = bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$", target))
    if is_ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    elif is_domain:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
    else:
        return jsonify({"error": "Provide a domain or IP address"})
    try:
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        attrs = data.get("data",{}).get("attributes",{})
        stats = attrs.get("last_analysis_stats",{})
        return jsonify({
            "target":      target,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  attrs.get("reputation", 0),
            "country":     attrs.get("country",""),
            "as_owner":    attrs.get("as_owner",""),
            "categories":  attrs.get("categories",{}),
            "vt_url":      f"https://www.virustotal.com/gui/{'ip-address' if is_ip else 'domain'}/{target}",
        })
    except Exception as e:
        return jsonify({"error": str(e)})



# ── HISTORY PAGE ──────────────────────────────────────────────────────────────

@app.route("/history")
@login_required
def history_page():
    db = Database()
    sessions = db.get_all_sessions()
    enriched = []
    for s in sessions:
        sc = db.get_severity_counts(s["id"])
        enriched.append({**dict(s), "severity_counts": sc})
    db.close()
    return render_template("history.html",
        sessions=enriched,
        page="history", title="Scan History"
    )


# ── SETTINGS PAGE ─────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings_page():
    import shutil
    return render_template("settings.html",
        nmap_available  = bool(shutil.which("nmap")),
        use_postgres    = bool(os.environ.get("DATABASE_URL")),
        nvd_key         = bool(os.environ.get("NVD_API_KEY")),
        screenshot_key  = bool(os.environ.get("SCREENSHOT_API_KEY")),
        shodan_key      = bool(os.environ.get("SHODAN_API_KEY")),
        virustotal_key  = bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        urlscan_key     = bool(os.environ.get("URLSCAN_API_KEY")),
        smtp_configured = bool(os.environ.get("SMTP_USER")),
        smtp_host       = os.environ.get("SMTP_HOST","smtp.gmail.com"),
        smtp_user       = os.environ.get("SMTP_USER",""),
        login_user      = os.environ.get("NETSCAN_USER","admin"),
        login_pass      = os.environ.get("NETSCAN_PASS","admin123"),
        page="settings", title="Settings"
    )


# ── REPORTS PAGE ──────────────────────────────────────────────────────────────

@app.route("/reports")
@login_required
def reports_page():
    db = Database()
    sessions = db.get_all_sessions()
    session_risks = {}
    for s in sessions:
        counts = db.get_severity_counts(s["id"])
        risk = "CRITICAL" if counts.get("Critical",0) > 0 else                "HIGH"     if counts.get("High",0) > 0     else                "MEDIUM"   if counts.get("Medium",0) > 0   else                "LOW"      if counts.get("Low",0) > 0       else "NONE"
        session_risks[s["id"]] = risk

    db_reports = db.get_all_report_files()
    db.close()

    reports = []
    for r in db_reports:
        size_kb = (r.get("file_size") or 0) // 1024
        date = (r.get("created_at","") or "")[:16].replace("T"," ")
        reports.append({
            "filename":   r["filename"],
            "type":       r["file_type"],
            "target":     r["target"],
            "session_id": r["session_id"],
            "risk":       session_risks.get(r["session_id"], "NONE"),
            "date":       date,
            "size":       f"{size_kb} KB",
        })

    pdf_count  = sum(1 for r in reports if r["type"] == "pdf")
    html_count = sum(1 for r in reports if r["type"] == "html")
    sess_ids   = set(r["session_id"] for r in reports)

    return render_template("reports.html",
        reports=reports,
        total_reports=len(reports),
        pdf_count=pdf_count,
        html_count=html_count,
        sessions_with_reports=len(sess_ids),
        page="reports", title="Reports"
    )


# ── API NOTIFICATIONS ─────────────────────────────────────────────────────────

@app.route("/api/notifications")
@login_required
def api_notifications():
    db     = Database()
    counts = db.get_severity_counts()
    db.close()
    notifs = []
    if counts.get("Critical",0) > 0:
        notifs.append({"message": f"{counts['Critical']} Critical vulnerability(ies) found — immediate action required", "type": "critical"})
    if counts.get("High",0) > 0:
        notifs.append({"message": f"{counts['High']} High severity finding(s) — address within 7 days", "type": "high"})
    return jsonify(notifs)


# ── API ACTIVITY FEED ─────────────────────────────────────────────────────────

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
        else:
            feed.append({"type":"scan","message":f"Scanning: {s['target']}","time":t,"badge":None,"badge_type":""})
    db.close()
    return jsonify(feed)


# ── API SEVERITY COUNTS ───────────────────────────────────────────────────────

@app.route("/api/severity-counts")
@login_required
def api_severity_counts():
    db     = Database()
    counts = db.get_severity_counts()
    db.close()
    return jsonify(counts)


# ── API SESSIONS ──────────────────────────────────────────────────────────────

@app.route("/api/sessions")
@login_required
def api_sessions():
    db       = Database()
    sessions = db.get_all_sessions()
    result   = []
    for s in sessions[:10]:
        sc = db.get_severity_counts(s["id"])
        result.append({
            "id":             s["id"],
            "target":         s["target"],
            "status":         s["status"],
            "started_at":     s.get("started_at",""),
            "severity_counts": sc
        })
    db.close()
    return jsonify(result)


# ── API SEARCH ────────────────────────────────────────────────────────────────




@app.route("/targets")
@login_required
def targets_page():
    db = Database()
    sessions = db.get_all_sessions()
    target_map = {}
    for s in sessions:
        name = s["target"]
        if name not in target_map:
            target_map[name] = {
                "name": name, "ip": None,
                "scan_count": 0, "recent_scans": [],
                "total_critical": 0, "total_high": 0,
                "total_medium": 0, "total_low": 0,
                "latest_risk": "NONE", "risk_history": [],
                "trend": "stable",
            }
        t = target_map[name]
        t["scan_count"] += 1
        counts = db.get_severity_counts(s["id"])
        t["total_critical"] += counts.get("Critical", 0)
        t["total_high"]     += counts.get("High", 0)
        t["total_medium"]   += counts.get("Medium", 0)
        t["total_low"]      += counts.get("Low", 0)
        total = sum(counts.values())
        risk = "CRITICAL" if counts.get("Critical",0)>0 else                "HIGH"     if counts.get("High",0)>0     else                "MEDIUM"   if counts.get("Medium",0)>0   else                "LOW"      if counts.get("Low",0)>0       else "NONE"
        t["risk_history"].append(risk)
        se = dict(s)
        se["total_findings"] = total
        t["recent_scans"].append(se)
        if not t["ip"]:
            hosts = db.get_hosts(s["id"])
            if hosts:
                t["ip"] = hosts[0].get("ip", "")

    for t in target_map.values():
        t["recent_scans"].sort(key=lambda x: x.get("started_at",""), reverse=True)
        if t["risk_history"]:
            t["latest_risk"] = t["risk_history"][-1]
            if len(t["risk_history"]) >= 2:
                ro = {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
                last = ro.get(t["risk_history"][-1], 0)
                prev = ro.get(t["risk_history"][-2], 0)
                t["trend"] = "worse" if last > prev else "better" if last < prev else "stable"

    targets = sorted(target_map.values(),
        key=lambda x: ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"NONE":4}.get(x["latest_risk"],4), x["name"])
    )
    db.close()
    return render_template("targets.html",
        targets=list(targets),
        page="targets", title="Targets"
    )



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))@app.route("/api/search")
@login_required
def api_search():
    q = request.args.get("q","").strip()
    if not q:
        return jsonify({"results":[]})

    results = []
    db = Database()
    sessions = db.get_all_sessions()

    filter_type = None
    query = q
    if ":" in q:
        parts = q.split(":",1)
        if parts[0].lower() in ("target","cve","risk","report","vuln","host","ip"):
            filter_type = parts[0].lower()
            query = parts[1].strip()
    qlo = query.lower()

    RISK_COLORS = {
        "CRITICAL": ("rgba(239,68,68,0.15)","#ef4444"),
        "HIGH":     ("rgba(249,115,22,0.15)","#f97316"),
        "MEDIUM":   ("rgba(234,179,8,0.15)","#eab308"),
        "LOW":      ("rgba(59,130,246,0.15)","#3b82f6"),
        "NONE":     ("rgba(100,116,139,0.15)","#64748b"),
    }

    def risk_badge(risk):
        risk = risk.upper()
        bg, col = RISK_COLORS.get(risk, RISK_COLORS["NONE"])
        return risk, bg, col

    def calc_risk(counts):
        if counts.get("Critical",0) > 0: return "CRITICAL"
        if counts.get("High",0) > 0:     return "HIGH"
        if counts.get("Medium",0) > 0:   return "MEDIUM"
        if counts.get("Low",0) > 0:      return "LOW"
        return "NONE"

    # Targets
    if filter_type in (None,"target","ip","host"):
        seen = set()
        for s in sessions:
            tgt = s["target"]
            if qlo in tgt.lower() and tgt not in seen:
                seen.add(tgt)
                counts = db.get_severity_counts(s["id"])
                rk = calc_risk(counts)
                rk, bg, col = risk_badge(rk)
                scan_count = sum(1 for x in sessions if x["target"] == tgt)
                results.append({
                    "icon":"🌐","title":tgt,
                    "subtitle":"Target " + str(scan_count) + " scan(s) Last scanned " + s.get("started_at","")[:10],
                    "url":"/scan/" + s["id"],
                    "badge":rk,"badge_bg":bg,"badge_color":col,
                })

    # Risk filter
    if filter_type == "risk":
        for s in sessions:
            counts = db.get_severity_counts(s["id"])
            rk = calc_risk(counts).lower()
            if qlo in rk:
                rk2, bg, col = risk_badge(rk)
                results.append({
                    "icon":"⚠️","title":s["target"],
                    "subtitle":"Risk " + rk2 + " " + s.get("started_at","")[:10],
                    "url":"/scan/" + s["id"],
                    "badge":rk2,"badge_bg":bg,"badge_color":col,
                })

    # CVEs
    if filter_type in (None,"cve"):
        seen_c = set()
        for s in sessions:
            for c in db.get_cve_findings(s["id"]):
                cid = c.get("cve_id","")
                if qlo in cid.lower() and cid not in seen_c:
                    seen_c.add(cid)
                    sev = c.get("severity","LOW").upper()
                    sev, bg, col = risk_badge(sev)
                    results.append({
                        "icon":"🔴","title":cid,
                        "subtitle":"Found on " + s["target"] + " CVSS " + str(c.get("cvss_score","N/A")),
                        "url":"/scan/" + s["id"],
                        "badge":sev,"badge_bg":bg,"badge_color":col,
                    })

    # Web vulns
    if filter_type in (None,"vuln"):
        seen_v = set()
        for s in sessions:
            for f in db.get_web_findings(s["id"]):
                vtype = f.get("vuln_type","")
                key = s["id"] + ":" + vtype
                if (qlo in vtype.lower() or qlo in f.get("description","").lower()) and key not in seen_v:
                    seen_v.add(key)
                    sev = f.get("severity","LOW").upper()
                    sev, bg, col = risk_badge(sev)
                    results.append({
                        "icon":"🐛","title":vtype or "Web Finding",
                        "subtitle":"Found on " + s["target"] + " " + f.get("url","")[:40],
                        "url":"/scan/" + s["id"],
                        "badge":sev,"badge_bg":bg,"badge_color":col,
                    })

    # Reports
    if filter_type in (None,"report"):
        for r in db.get_all_report_files():
            if qlo in r.get("target","").lower():
                results.append({
                    "icon":"📄" if r["file_type"]=="pdf" else "🌐",
                    "title":r.get("target","Unknown"),
                    "subtitle":r["file_type"].upper() + " Report " + r.get("created_at","")[:10],
                    "url":"/report/" + r["filename"],
                    "badge":None,
                })

    db.close()
    return jsonify({"results":results[:25]})
