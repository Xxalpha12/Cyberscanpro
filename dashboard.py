"""
NetScan Pro - Web Dashboard (Flask)
"""

from flask import Flask, render_template, request, jsonify, send_file, abort
import os
import threading
from datetime import datetime
from modules.database import Database
from modules.logger import get_logger

logger = get_logger(__name__)

app = Flask(__name__)
app.secret_key = "netscampro-dev-secret-change-in-production"

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
PORT = int(os.environ.get("PORT", 5000))

active_scans = {}


@app.route("/")
def index():
    db = Database()
    sessions = db.get_all_sessions()
    severity_counts = db.get_severity_counts()
    total_findings = db.get_total_findings()
    db.close()
    return render_template("dashboard.html", sessions=sessions,
                           severity_counts=severity_counts,
                           total_findings=total_findings,
                           page="home", title="NetScan Pro Dashboard")


@app.route("/scan/new", methods=["GET"])
def new_scan():
    return render_template("new_scan.html", page="new_scan", title="New Scan")


@app.route("/scan/run", methods=["POST"])
def run_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP or CIDR is required."}), 400

    from modules.network_scanner import NetworkScanner
    from modules.web_scanner import WebScanner
    from modules.web_tester import WebTester
    from modules.cve_scanner import CVEScanner
    from modules.report_generator import ReportGenerator

    db = Database()
    session_id = db.create_session(target)
    db.close()

    active_scans[session_id] = {
        "status": "running",
        "log": [],
        "report_paths": [],
        "progress": 0
    }

    def _run():
        log = active_scans[session_id]["log"]
        try:
            db = Database()
            log.append(f"[{_ts()}] Scan started for target: {target}")
            active_scans[session_id]["progress"] = 5

            # Network scan
            log.append(f"[{_ts()}] Running Network Scanner...")
            scanner = NetworkScanner(
                target=target,
                port_range=data.get("port_range", "1-1024"),
                scan_type=data.get("scan_type", "quick")
            )
            hosts = scanner.run()
            db.save_hosts(session_id, hosts)
            active_scans[session_id]["progress"] = 30
            log.append(f"[{_ts()}] Network scan complete. {len(hosts)} host(s) found.")

            # Web + CVE simultaneously
            log.append(f"[{_ts()}] Launching Web Scanner + CVE Scanner simultaneously...")
            web_findings = []
            cve_findings = []

            def run_web():
                try:
                    header_scanner = WebScanner(hosts=hosts)
                    header_results = header_scanner.run()
                    vuln_tester = WebTester(hosts=hosts)
                    vuln_results = vuln_tester.run()
                    combined = header_results + vuln_results
                    web_findings.extend(combined)
                    log.append(f"[{_ts()}] Web scan done — Header: {len(header_results)} | Vuln: {len(vuln_results)}")
                except Exception as e:
                    log.append(f"[{_ts()}] Web scan error: {e}")

            def run_cve():
                try:
                    cve_scanner = CVEScanner(hosts=hosts)
                    results = cve_scanner.run()
                    cve_findings.extend(results)
                    log.append(f"[{_ts()}] CVE scan done — {len(results)} finding(s).")
                except Exception as e:
                    log.append(f"[{_ts()}] CVE scan error: {e}")

            web_thread = threading.Thread(target=run_web, name="WebScanner")
            cve_thread = threading.Thread(target=run_cve, name="CVEScanner")
            web_thread.start()
            cve_thread.start()
            web_thread.join()
            cve_thread.join()

            active_scans[session_id]["progress"] = 75
            db.save_web_findings(session_id, web_findings)
            db.save_cve_findings(session_id, cve_findings)
            log.append(f"[{_ts()}] Total — Web: {len(web_findings)} | CVE: {len(cve_findings)}")

            # Report
            log.append(f"[{_ts()}] Generating report...")
            active_scans[session_id]["progress"] = 88
            gen = ReportGenerator(
                session_id=session_id, target=target,
                hosts=hosts, web_findings=web_findings,
                cve_findings=cve_findings,
                output_format=data.get("output_format", "both")
            )
            paths = gen.generate()
            active_scans[session_id]["report_paths"] = paths
            db.complete_session(session_id)
            db.close()

            for p in paths:
                log.append(f"[{_ts()}] Report saved: {os.path.basename(p)}")

            active_scans[session_id]["status"] = "completed"
            active_scans[session_id]["progress"] = 100
            log.append(f"[{_ts()}] Scan completed successfully.")

        except Exception as e:
            active_scans[session_id]["status"] = "error"
            active_scans[session_id]["progress"] = 0
            active_scans[session_id]["log"].append(f"[{_ts()}] ERROR: {str(e)}")
            logger.error(f"Scan error (session {session_id}): {e}")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return jsonify({"session_id": session_id, "status": "started"})


@app.route("/scan/<session_id>/status")
def scan_status(session_id):
    if session_id not in active_scans:
        return jsonify({"status": "not_found", "log": [], "progress": 0})
    scan = active_scans[session_id]
    return jsonify({
        "status":       scan["status"],
        "log":          scan["log"],
        "progress":     scan.get("progress", 0),
        "report_paths": [os.path.basename(p) for p in scan.get("report_paths", [])]
    })


@app.route("/scan/<session_id>")
def view_scan(session_id):
    db = Database()
    session = db.get_session(session_id)
    if not session:
        abort(404)
    hosts        = db.get_hosts(session_id)
    web_findings = db.get_web_findings(session_id)
    cve_findings = db.get_cve_findings(session_id)
    severity_counts = db.get_severity_counts(session_id)
    total_findings = db.get_total_findings(session_id)
    db.close()
    return render_template(
        "scan_detail.html",
        session=session, hosts=hosts,
        web_findings=web_findings, cve_findings=cve_findings,
        severity_counts=severity_counts,
        total_findings=total_findings,
        page="results", title=f"Scan {session_id}"
    )


@app.route("/scan/<session_id>/delete", methods=["POST"])
def delete_scan(session_id):
    db = Database()
    session = db.get_session(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    db.delete_session(session_id)
    db.close()
    return jsonify({"success": True})


@app.route("/report/<filename>")
def download_report(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, as_attachment=True)


@app.route("/api/sessions")
def api_sessions():
    db = Database()
    sessions = db.get_all_sessions()
    db.close()
    return jsonify(sessions)


@app.route("/api/severity-counts")
def api_severity_counts():
    """API endpoint for live severity counts — used by dashboard auto-refresh."""
    db = Database()
    counts = db.get_severity_counts()
    total = db.get_total_findings()
    sessions = db.get_all_sessions()
    db.close()
    return jsonify({
        "severity_counts": counts,
        "total_findings": total,
        "session_count": len(sessions),
        "completed": len([s for s in sessions if s["status"] == "completed"]),
        "running": len([s for s in sessions if s["status"] == "running"]),
        "errors": len([s for s in sessions if s["status"] == "error"])
    })


def _ts():
    return datetime.now().strftime("%H:%M:%S")
