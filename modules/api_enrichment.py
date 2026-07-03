"""
CyberScan Pro - API Enrichment Module
Enriches scan results with data from external threat intelligence APIs.
All functions are non-blocking — if an API fails or key is missing, 
scanning continues normally without interruption.
"""

import os
import json
import urllib.request
import urllib.parse
import logging

logger = logging.getLogger(__name__)


def enrich_target(ip: str, hostname: str, progress_cb=None) -> dict:
    """
    Run all available API enrichments on a target.
    Returns a dict of enrichment data to attach to the host record.
    """
    enrichment = {}

    def _log(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    # ── Shodan ────────────────────────────────────────────────────────────────
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if shodan_key and ip:
        try:
            _log(f"Querying Shodan for {ip}...")
            url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
            req = urllib.request.Request(url, headers={"User-Agent": "CyberScanPro/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            enrichment["shodan"] = {
                "org":          data.get("org", ""),
                "isp":          data.get("isp", ""),
                "country":      data.get("country_name", ""),
                "city":         data.get("city", ""),
                "os":           data.get("os", ""),
                "open_ports":   data.get("ports", []),
                "vulns":        list(data.get("vulns", {}).keys()),
                "tags":         data.get("tags", []),
                "last_update":  data.get("last_update", ""),
                "hostnames":    data.get("hostnames", []),
            }
            _log(f"Shodan: {len(enrichment['shodan']['open_ports'])} ports, {len(enrichment['shodan']['vulns'])} vulns")
        except Exception as e:
            logger.warning(f"Shodan enrichment failed: {e}")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    target = hostname or ip
    if vt_key and target:
        try:
            _log(f"Querying VirusTotal for {target}...")
            import re
            is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
            if is_ip:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                clean = target.lstrip("www.")
                url = f"https://www.virustotal.com/api/v3/domains/{clean}"
            req = urllib.request.Request(url, headers={"x-apikey": vt_key})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            enrichment["virustotal"] = {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "country":    attrs.get("country", ""),
                "as_owner":   attrs.get("as_owner", ""),
                "vt_url":     f"https://www.virustotal.com/gui/{'ip-address' if is_ip else 'domain'}/{target}",
            }
            mal = enrichment["virustotal"]["malicious"]
            _log(f"VirusTotal: {mal} malicious detections")
            if mal > 0:
                _log(f"WARNING: {target} flagged as malicious by {mal} VirusTotal engines")
        except Exception as e:
            logger.warning(f"VirusTotal enrichment failed: {e}")

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if abuse_key and ip:
        try:
            _log(f"Querying AbuseIPDB for {ip}...")
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={
                "Key": abuse_key,
                "Accept": "application/json"
            })
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read())
            d = data.get("data", {})
            enrichment["abuseipdb"] = {
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "total_reports":  d.get("totalReports", 0),
                "country":        d.get("countryCode", ""),
                "isp":            d.get("isp", ""),
                "domain":         d.get("domain", ""),
                "usage_type":     d.get("usageType", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
                "last_reported":  (d.get("lastReportedAt") or "")[:10],
            }
            score = enrichment["abuseipdb"]["abuse_score"]
            _log(f"AbuseIPDB: abuse score {score}%")
            if score > 25:
                _log(f"WARNING: {ip} has high abuse score ({score}%) on AbuseIPDB")
        except Exception as e:
            logger.warning(f"AbuseIPDB enrichment failed: {e}")

    # ── URLScan.io ────────────────────────────────────────────────────────────
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "")
    if urlscan_key and hostname:
        try:
            _log(f"Submitting {hostname} to URLScan.io...")
            # Submit scan
            submit_data = json.dumps({"url": f"https://{hostname}", "visibility": "private"}).encode()
            req = urllib.request.Request(
                "https://urlscan.io/api/v1/scan/",
                data=submit_data,
                headers={"API-Key": urlscan_key, "Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                result = json.loads(r.read())
            scan_uuid = result.get("uuid", "")
            if scan_uuid:
                enrichment["urlscan"] = {
                    "uuid":       scan_uuid,
                    "result_url": f"https://urlscan.io/result/{scan_uuid}/",
                    "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                    "status":     "submitted",
                }
                _log(f"URLScan.io: submitted — result at urlscan.io/result/{scan_uuid}/")
        except Exception as e:
            logger.warning(f"URLScan.io enrichment failed: {e}")

    return enrichment


def get_shodan_cves(ip: str) -> list:
    """Get CVEs for an IP directly from Shodan — supplements NVD lookups."""
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if not shodan_key or not ip:
        return []
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberScanPro/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        vulns = data.get("vulns", {})
        result = []
        for cve_id, details in vulns.items():
            result.append({
                "cve_id":      cve_id,
                "cvss_score":  details.get("cvss", 0.0),
                "severity":    _cvss_to_severity(details.get("cvss", 0.0)),
                "description": details.get("summary", ""),
                "reference":   f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source":      "Shodan",
            })
        return result
    except Exception as e:
        logger.warning(f"Shodan CVE fetch failed: {e}")
        return []


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0:    return "Low"
    return "Low"
