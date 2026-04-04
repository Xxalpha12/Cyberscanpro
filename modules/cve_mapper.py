"""
NetScan Pro - CVE Mapper Module
Maps discovered services to known CVEs using the
NVD (National Vulnerability Database) REST API v2.

Requires internet access to query: https://services.nvd.nist.gov/

Usage (internal):
    mapper = CVEMapper(hosts=hosts)
    cve_findings = mapper.run()
"""

import time
import requests
from modules.logger import get_logger

logger = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 0.6   # NVD rate limit: ~5 req/sec without API key
MAX_CVES_PER_SERVICE = 5

CVSS_SEVERITY = {
    "critical": (9.0, 10.0),
    "high":     (7.0, 8.9),
    "medium":   (4.0, 6.9),
    "low":      (0.1, 3.9),
    "none":     (0.0, 0.0)
}


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS score to a human-readable severity label."""
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    if score > 0.0:   return "Low"
    return "None"


class CVEMapper:
    """
    Queries the NVD API to find CVEs matching discovered services.
    Results are cached in memory to avoid duplicate API calls.
    """

    def __init__(self, hosts: list, verbose: bool = False, api_key: str = None):
        self.hosts = hosts
        self.verbose = verbose
        self.api_key = api_key  # Optional: set for higher NVD rate limits
        self.cache = {}          # { "service_version_string": [cve_list] }
        self.findings = []

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "NetScanPro/1.0 (security research)"
        })
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def run(self) -> list:
        """
        Main entry point. Iterates over all hosts and ports,
        queries NVD for each service, and returns CVE findings.
        """
        logger.info("Starting CVE mapping...")

        for host in self.hosts:
            ip = host.get("ip")
            for port_info in host.get("ports", []):
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                port    = port_info.get("port")

                if not service or service in ("unknown", "N/A"):
                    continue

                query = self._build_query(service, version)
                if not query:
                    continue

                cves = self._lookup_cves(query)
                for cve in cves:
                    finding = {
                        "host_ip":     ip,
                        "port":        port,
                        "service":     f"{service} {version}".strip(),
                        "cve_id":      cve["cve_id"],
                        "cvss_score":  cve["cvss_score"],
                        "severity":    cve["severity"],
                        "description": cve["description"],
                        "reference":   cve["reference"]
                    }
                    self.findings.append(finding)

                    if self.verbose:
                        logger.info(
                            f"  [{cve['severity']}] {cve['cve_id']} — "
                            f"{ip}:{port} ({service}) — CVSS: {cve['cvss_score']}"
                        )

        logger.info(f"CVE mapping complete. {len(self.findings)} finding(s).")
        return self.findings

    # ── QUERY BUILDER ─────────────────────────────────────

    def _build_query(self, service: str, version: str) -> str:
        """
        Build a CPE-style keyword query for the NVD API.
        Cleans and normalizes service/version strings.
        """
        # Skip non-specific services
        skip = {"tcpwrapped", "unknown", "n/a", "filtered", ""}
        if service.lower() in skip:
            return ""

        # Build keyword string: e.g. "Apache 2.4.41"
        parts = [service]
        if version and version.lower() not in skip:
            # Extract first version-like token
            for token in version.split():
                if any(c.isdigit() for c in token):
                    parts.append(token)
                    break
        return " ".join(parts)

    # ── NVD API LOOKUP ────────────────────────────────────

    def _lookup_cves(self, query: str) -> list:
        """
        Query the NVD API for CVEs matching the keyword string.
        Uses in-memory cache to avoid redundant requests.
        """
        if query in self.cache:
            return self.cache[query]

        params = {
            "keywordSearch": query,
            "resultsPerPage": MAX_CVES_PER_SERVICE
        }

        try:
            time.sleep(REQUEST_DELAY)
            response = self.session.get(NVD_API_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.warning(f"NVD API request failed for '{query}': {e}")
            self.cache[query] = []
            return []
        except ValueError:
            logger.warning(f"NVD API returned invalid JSON for '{query}'")
            self.cache[query] = []
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            parsed = self._parse_cve(cve_data)
            if parsed:
                cves.append(parsed)

        self.cache[query] = cves
        return cves

    # ── CVE PARSER ────────────────────────────────────────

    def _parse_cve(self, cve_data: dict) -> dict:
        """Parse a single CVE entry from NVD API response."""
        cve_id = cve_data.get("id", "N/A")

        # Description (English preferred)
        descriptions = cve_data.get("descriptions", [])
        description = "No description available."
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", description)
                break

        # CVSS score — try v3.1, fallback to v3.0, then v2
        cvss_score = 0.0
        metrics = cve_data.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                m = metrics[metric_key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        severity = cvss_to_severity(cvss_score)

        # Reference URL
        refs = cve_data.get("references", [])
        reference = refs[0].get("url", f"https://nvd.nist.gov/vuln/detail/{cve_id}") if refs else \
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        return {
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "severity":    severity,
            "description": description[:500],
            "reference":   reference
        }

    # ── SEVERITY SUMMARY ─────────────────────────────────

    def get_severity_summary(self) -> dict:
        """Return a count of findings grouped by severity."""
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in self.findings:
            sev = f.get("severity", "None")
            if sev in summary:
                summary[sev] += 1
        return summary
