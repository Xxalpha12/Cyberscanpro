"""
NetScan Pro - Database Module
Handles all SQLite operations for storing scan sessions, hosts,
web findings, and CVE records.
"""

import sqlite3
import os
import uuid
from datetime import datetime
from modules.logger import get_logger

logger = get_logger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "netscampro.db")


class Database:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        logger.info(f"Database initialized at {DB_PATH}")

    def _init_schema(self):
        """Create all tables if they don't exist."""
        cursor = self.conn.cursor()

        # Scan sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT DEFAULT 'running'
            )
        """)

        # Discovered hosts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                os TEXT,
                status TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)

        # Open ports and services per host
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        """)

        # Web application vulnerability findings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)

        # CVE findings mapped to services
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                reference TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)

        self.conn.commit()
        logger.info("Database schema initialized.")

    # ── SESSION ──────────────────────────────────────────

    def create_session(self, target: str) -> str:
        """Create a new scan session and return its ID."""
        session_id = str(uuid.uuid4())[:8]
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (id, target, started_at) VALUES (?, ?, ?)",
            (session_id, target, datetime.now().isoformat())
        )
        self.conn.commit()
        return session_id

    def complete_session(self, session_id: str):
        """Mark a session as completed."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE sessions SET completed_at=?, status=? WHERE id=?",
            (datetime.now().isoformat(), "completed", session_id)
        )
        self.conn.commit()

    def get_all_sessions(self):
        """Return all scan sessions."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions ORDER BY started_at DESC")
        return [dict(row) for row in cursor.fetchall()]

    def get_session(self, session_id: str):
        """Return a single session by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    # ── HOSTS ────────────────────────────────────────────

    def save_hosts(self, session_id: str, hosts: list):
        """
        Save discovered hosts and their open ports.

        Expected host format:
        {
            "ip": "192.168.1.10",
            "hostname": "device.local",
            "os": "Linux 4.x",
            "status": "up",
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service": "http", "version": "Apache 2.4.41"}
            ]
        }
        """
        cursor = self.conn.cursor()
        for host in hosts:
            cursor.execute(
                """INSERT INTO hosts (session_id, ip, hostname, os, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, host.get("ip"), host.get("hostname"),
                 host.get("os"), host.get("status", "up"))
            )
            host_id = cursor.lastrowid

            for port in host.get("ports", []):
                cursor.execute(
                    """INSERT INTO ports (host_id, port, protocol, state, service, version)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (host_id, port.get("port"), port.get("protocol", "tcp"),
                     port.get("state", "open"), port.get("service"),
                     port.get("version"))
                )
        self.conn.commit()

    def get_hosts(self, session_id: str) -> list:
        """Return all hosts and their ports for a session."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM hosts WHERE session_id=?", (session_id,))
        hosts = []
        for host_row in cursor.fetchall():
            host = dict(host_row)
            cursor.execute("SELECT * FROM ports WHERE host_id=?", (host["id"],))
            host["ports"] = [dict(p) for p in cursor.fetchall()]
            hosts.append(host)
        return hosts

    # ── WEB FINDINGS ─────────────────────────────────────

    def save_web_findings(self, session_id: str, findings: list):
        """
        Save web vulnerability findings.

        Expected finding format:
        {
            "host_ip": "192.168.1.10",
            "url": "http://192.168.1.10/login?id=1",
            "vuln_type": "SQL Injection",
            "severity": "High",
            "description": "...",
            "evidence": "Error: SQL syntax...",
            "recommendation": "Use parameterized queries."
        }
        """
        cursor = self.conn.cursor()
        for f in findings:
            cursor.execute(
                """INSERT INTO web_findings
                   (session_id, host_ip, url, vuln_type, severity,
                    description, evidence, recommendation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, f.get("host_ip"), f.get("url"),
                 f.get("vuln_type"), f.get("severity"),
                 f.get("description"), f.get("evidence"),
                 f.get("recommendation"))
            )
        self.conn.commit()

    def get_web_findings(self, session_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM web_findings WHERE session_id=?", (session_id,))
        return [dict(row) for row in cursor.fetchall()]

    # ── CVE FINDINGS ─────────────────────────────────────

    def save_cve_findings(self, session_id: str, findings: list):
        """
        Save CVE findings.

        Expected finding format:
        {
            "host_ip": "192.168.1.10",
            "port": 80,
            "service": "Apache 2.4.41",
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "severity": "Critical",
            "description": "Path traversal vulnerability...",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
        }
        """
        cursor = self.conn.cursor()
        for f in findings:
            cursor.execute(
                """INSERT INTO cve_findings
                   (session_id, host_ip, port, service, cve_id,
                    cvss_score, severity, description, reference)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, f.get("host_ip"), f.get("port"),
                 f.get("service"), f.get("cve_id"),
                 f.get("cvss_score"), f.get("severity"),
                 f.get("description"), f.get("reference"))
            )
        self.conn.commit()

    def get_cve_findings(self, session_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cve_findings WHERE session_id=?", (session_id,))
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        self.conn.close()
