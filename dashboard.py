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




# ── REPORTS PAGE ─────────────────────────────────────────────────────────────

@app.route("/reports")
@login_required
def reports_page():
    db = Database()
    sessions = db.get_all_sessions()
    session_risks = {}
    for s in sessions:
        counts = db.get_severity_counts(s["id"])
        risk = "CRITICAL" if counts.get("Critical",0) > 0 else \
               "HIGH"     if counts.get("High",0) > 0     else \
               "MEDIUM"   if counts.get("Medium",0) > 0   else \
               "LOW"      if counts.get("Low",0) > 0       else "NONE"
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




# ── GLOBAL SEARCH API ─────────────────────────────────────────────────────────

@app.route("/api/search")
@login_required
def api_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"results": []})

    results = []
    db = Database()
    sessions = db.get_all_sessions()

    # Parse search operators
    filter_type = None
    query = q
    if ":" in q:
        prefix, rest = q.split(":", 1)
        if prefix.lower() in ("target", "cve", "risk", "report"):
            filter_type = prefix.lower()
            query = rest.strip()

    query_lower = query.lower()

    # Search targets/sessions
    if filter_type in (None, "target"):
        seen_targets = set()
        for s in sessions:
            if query_lower in s["target"].lower() and s["target"] not in seen_targets:
                seen_targets.add(s["target"])
                counts = db.get_severity_counts(s["id"])
                risk = "CRITICAL" if counts.get("Critical",0) > 0 else \
                       "HIGH" if counts.get("High",0) > 0 else \
                       "MEDIUM" if counts.get("Medium",0) > 0 else \
                       "LOW" if counts.get("Low",0) > 0 else "NONE"
                badge_colors = {
                    "CRITICAL": ("rgba(239,68,68,0.15)", "#ef4444"),
                    "HIGH": ("rgba(249,115,22,0.15)", "#f97316"),
                    "MEDIUM": ("rgba(234,179,8,0.15)", "#eab308"),
                    "LOW": ("rgba(59,130,246,0.15)", "#3b82f6"),
                    "NONE": ("rgba(100,116,139,0.15)", "#64748b"),
                }
                bg, color = badge_colors.get(risk, badge_colors["NONE"])
                results.append({
                    "icon": "🌐", "title": s["target"],
                    "subtitle": f"Target · Last scanned {s.get('started_at','')[:10]}",
                    "url": f"/scan/{s['id']}",
                    "badge": risk, "badge_bg": bg, "badge_color": color,
                })

    # Search by risk level
    if filter_type == "risk":
        for s in sessions:
            counts = db.get_severity_counts(s["id"])
            risk = "critical" if counts.get("Critical",0)>0 else \
                   "high" if counts.get("High",0)>0 else \
                   "medium" if counts.get("Medium",0)>0 else \
                   "low" if counts.get("Low",0)>0 else "none"
            if query_lower in risk:
                results.append({
                    "icon": "⚠️", "title": s["target"],
                    "subtitle": f"Risk level: {risk.upper()}",
                    "url": f"/scan/{s['id']}",
                    "badge": risk.upper(), "badge_bg": "rgba(239,68,68,0.15)", "badge_color": "#ef4444",
                })

    # Search CVEs
    if filter_type in (None, "cve"):
        for s in sessions:
            cves = db.get_cve_findings(s["id"])
            for c in cves:
                if query_lower in c.get("cve_id","").lower():
                    results.append({
                        "icon": "🔴", "title": c.get("cve_id",""),
                        "subtitle": f"Found on {s['target']} · CVSS {c.get('cvss_score','N/A')}",
                        "url": f"/scan/{s['id']}",
                        "badge": c.get("severity","").upper(), "badge_bg": "rgba(239,68,68,0.15)", "badge_color": "#ef4444",
                    })

    # Search reports
    if filter_type in (None, "report"):
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        if os.path.exists(output_dir):
            session_targets = {s["id"]: s["target"] for s in sessions}
            for f in os.listdir(output_dir):
                if not (f.endswith(".pdf") or f.endswith(".html")):
                    continue
                parts = f.replace("cyberscanpro_report_","").split("_")
                sid = parts[0] if parts else ""
                target = session_targets.get(sid, "")
                if query_lower in target.lower():
                    results.append({
                        "icon": "📄" if f.endswith(".pdf") else "🌐",
                        "title": target,
                        "subtitle": f"{'PDF' if f.endswith('.pdf') else 'HTML'} Report",
                        "url": f"/report/{f}",
                        "badge": None,
                    })

    db.close()
    return jsonify({"results": results[:20]})




# ── TARGETS PAGE ──────────────────────────────────────────────────────────────

@app.route("/targets")
@login_required
def targets_page():
    db = Database()
    sessions = db.get_all_sessions()

    # Group sessions by target hostname
    target_map = {}
    for s in sessions:
        name = s["target"]
        if name not in target_map:
            target_map[name] = {
                "name":           name,
                "ip":             None,
                "scan_count":     0,
                "recent_scans":   [],
                "total_critical": 0,
                "total_high":     0,
                "total_medium":   0,
                "total_low":      0,
                "latest_risk":    "NONE",
                "risk_history":   [],
                "trend":          "stable",
                "reports":        [],
            }

        t = target_map[name]
        t["scan_count"] += 1

        # Severity counts for this scan
        counts = db.get_severity_counts(s["id"])
        crit   = counts.get("Critical", 0)
        high   = counts.get("High", 0)
        med    = counts.get("Medium", 0)
        low    = counts.get("Low", 0)
        total  = crit + high + med + low

        t["total_critical"] += crit
        t["total_high"]     += high
        t["total_medium"]   += med
        t["total_low"]      += low

        risk = "CRITICAL" if crit > 0 else \
               "HIGH"     if high > 0  else \
               "MEDIUM"   if med  > 0  else \
               "LOW"      if low  > 0  else "NONE"
        t["risk_history"].append(risk)

        # Enrich scan entry
        scan_entry = dict(s)
        scan_entry["total_findings"] = total
        t["recent_scans"].append(scan_entry)

        # Get host IP from first host found
        if not t["ip"]:
            hosts = db.get_hosts(s["id"])
            if hosts:
                t["ip"] = hosts[0].get("ip", "")

        # Reports for this session
        reps = db.get_reports_for_session(s["id"])
        for r in reps:
            if r not in t["reports"]:
                t["reports"].append(r)

    # Sort recent_scans newest first, compute latest risk and trend
    for t in target_map.values():
        t["recent_scans"].sort(key=lambda x: x.get("started_at",""), reverse=True)
        if t["risk_history"]:
            t["latest_risk"] = t["risk_history"][-1]
            # Trend: compare last scan vs second-to-last
            if len(t["risk_history"]) >= 2:
                risk_order = {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
                last  = risk_order.get(t["risk_history"][-1], 0)
                prev  = risk_order.get(t["risk_history"][-2], 0)
                if last > prev:
                    t["trend"] = "worse"
                elif last < prev:
                    t["trend"] = "better"
                else:
                    t["trend"] = "stable"

    targets = sorted(
        target_map.values(),
        key=lambda x: ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"NONE":4}.get(x["latest_risk"],4), x["name"])
    )

    db.close()

    return render_template("targets.html",
        targets=list(targets),
        page="targets",
        title="Targets"
    )


# ── SUPABASE KEEP-ALIVE (prevents free-tier auto-pause) ──────────────────────
import threading

def _supabase_keepalive():
    """Ping the database every 3 days to prevent Supabase free-tier pausing."""
    import time
    while True:
        # Wait 3 days (259200 seconds)
        time.sleep(259200)
        try:
            db = Database()
            c = db.conn.cursor()
            c.execute("SELECT 1")
            db.close()
            import logging
            logging.getLogger(__name__).info("Supabase keep-alive ping sent")
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Keep-alive ping failed: {e}")

# Only start keep-alive thread when running on Render (PostgreSQL mode)
if os.environ.get("DATABASE_URL"):
    _ka_thread = threading.Thread(target=_supabase_keepalive, daemon=True)
    _ka_thread.start()



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
