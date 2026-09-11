"""
CyberScan Pro - Database Module
Supports both SQLite (local) and PostgreSQL (Supabase cloud).
"""

import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from modules.logger import get_logger

logger = get_logger(__name__)

DB_PATH      = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "cyberscanpro.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    try:
        import psycopg2
        import psycopg2.extras
        logger.info("Using PostgreSQL (Supabase) -- persistent storage")
    except ImportError:
        USE_POSTGRES = False
        logger.warning("psycopg2 not installed -- falling back to SQLite")
else:
    logger.info("Using SQLite -- local storage")


class Database:
    def __init__(self):
        if USE_POSTGRES:
            self.conn = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
                sslmode="require",
                connect_timeout=10,
            )
            self.conn.autocommit = False
            self._pg = True
        else:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self._pg = False
        self._init_schema()

    def _q(self, sql):
        """Convert ? placeholders to %s for PostgreSQL."""
        if self._pg:
            return sql.replace("?", "%s")
        return sql

    def _init_schema(self):
        c = self.conn.cursor()
        if self._pg:
            c.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT DEFAULT 'running'
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    ip TEXT,
                    hostname TEXT,
                    os TEXT,
                    status TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id BIGSERIAL PRIMARY KEY,
                    host_id BIGINT NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    service TEXT,
                    version TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS web_findings (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    host_ip TEXT,
                    url TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS cve_findings (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    host_ip TEXT,
                    port INTEGER,
                    service TEXT,
                    cve_id TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    description TEXT,
                    reference TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS deleted_sessions (
                    id TEXT PRIMARY KEY,
                    deleted_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    message TEXT,
                    created_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_status (
                    session_id TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'running',
                    progress INTEGER DEFAULT 0,
                    hosts_found INTEGER DEFAULT 0,
                    web_count INTEGER DEFAULT 0,
                    cve_count INTEGER DEFAULT 0,
                    report_paths TEXT DEFAULT '',
                    updated_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_notes (
                    session_id TEXT PRIMARY KEY,
                    notes TEXT DEFAULT '',
                    updated_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id BIGSERIAL PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_type TEXT DEFAULT 'quick',
                    port_range TEXT DEFAULT '1-1024',
                    frequency TEXT NOT NULL,
                    next_run TEXT NOT NULL,
                    last_run TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TEXT
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT DEFAULT 'running'
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ip TEXT,
                    hostname TEXT,
                    os TEXT,
                    status TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    service TEXT,
                    version TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS web_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    host_ip TEXT,
                    url TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS cve_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    host_ip TEXT,
                    port INTEGER,
                    service TEXT,
                    cve_id TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    description TEXT,
                    reference TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS deleted_sessions (
                    id TEXT PRIMARY KEY,
                    deleted_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    message TEXT,
                    created_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_status (
                    session_id TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'running',
                    progress INTEGER DEFAULT 0,
                    hosts_found INTEGER DEFAULT 0,
                    web_count INTEGER DEFAULT 0,
                    cve_count INTEGER DEFAULT 0,
                    report_paths TEXT DEFAULT '',
                    updated_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_notes (
                    session_id TEXT PRIMARY KEY,
                    notes TEXT DEFAULT '',
                    updated_at TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT DEFAULT 'quick',
                    port_range TEXT DEFAULT '1-1024',
                    frequency TEXT NOT NULL,
                    next_run TEXT NOT NULL,
                    last_run TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TEXT
                )
            """)
        self.conn.commit()
        self._init_org_schema()

    # ── ORGANIZATIONS / ASSETS / USERS SCHEMA ───────────────────────────────────

    def _init_org_schema(self):
        """Users, Organizations, Org Membership (roles) and Assets.
        Added as a separate step (rather than inline above) so it layers
        cleanly on top of existing installs without touching the original
        scan tables. sessions.org_id / sessions.asset_id are added via
        best-effort ALTER TABLE so existing databases upgrade in place."""
        c = self.conn.cursor()
        if self._pg:
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_user_id BIGINT,
                    created_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS org_members (
                    org_id BIGINT NOT NULL,
                    user_id BIGINT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    joined_at TEXT NOT NULL,
                    PRIMARY KEY (org_id, user_id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id BIGSERIAL PRIMARY KEY,
                    org_id BIGINT NOT NULL,
                    name TEXT NOT NULL,
                    asset_type TEXT DEFAULT 'server',
                    address TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    added_by BIGINT,
                    created_at TEXT NOT NULL
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    owner_user_id INTEGER,
                    created_at TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS org_members (
                    org_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    joined_at TEXT NOT NULL,
                    PRIMARY KEY (org_id, user_id)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    asset_type TEXT DEFAULT 'server',
                    address TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    added_by INTEGER,
                    created_at TEXT NOT NULL
                )
            """)
        self.conn.commit()

        # Best-effort column additions to the existing `sessions` table so
        # scans can optionally be tied to an organization/asset. Safe to
        # run repeatedly — errors (column already exists) are swallowed.
        for stmt in (
            "ALTER TABLE sessions ADD COLUMN org_id INTEGER",
            "ALTER TABLE sessions ADD COLUMN asset_id INTEGER",
        ):
            try:
                c.execute(stmt)
                self.conn.commit()
            except Exception:
                self.conn.rollback()

    def ensure_default_user_and_org(self, username: str, password_hash: str) -> None:
        """First-run bootstrap: if no users exist yet, create the admin
        account (credentials come from NETSCAN_USER/NETSCAN_PASS) plus a
        default organization they own, so existing installs keep working
        with zero extra setup."""
        c = self.conn.cursor()
        c.execute("SELECT COUNT(*) AS n FROM users")
        row = c.fetchone()
        count = row["n"] if isinstance(row, dict) else row[0]
        if count and count > 0:
            return
        user_id = self.create_user(username, password_hash)
        self.create_organization("Default Organization", user_id)

    # ── USERS ────────────────────────────────────────────────────────────────

    def create_user(self, username: str, password_hash: str) -> int:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO users (username,password_hash,created_at) VALUES (%s,%s,%s) RETURNING id",
                (username, password_hash, now)
            )
            self.conn.commit()
            return c.fetchone()["id"]
        else:
            c.execute(
                "INSERT INTO users (username,password_hash,created_at) VALUES (?,?,?)",
                (username, password_hash, now)
            )
            self.conn.commit()
            return c.lastrowid

    def get_user_by_username(self, username: str):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM users WHERE username=?"), (username,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM users WHERE id=?"), (user_id,))
        row = c.fetchone()
        return dict(row) if row else None

    # ── ORGANIZATIONS ────────────────────────────────────────────────────────

    def create_organization(self, name: str, owner_user_id: int) -> int:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO organizations (name,owner_user_id,created_at) VALUES (%s,%s,%s) RETURNING id",
                (name, owner_user_id, now)
            )
            org_id = c.fetchone()["id"]
        else:
            c.execute(
                "INSERT INTO organizations (name,owner_user_id,created_at) VALUES (?,?,?)",
                (name, owner_user_id, now)
            )
            org_id = c.lastrowid
        self.conn.commit()
        self.add_org_member(org_id, owner_user_id, "owner")
        return org_id

    def add_org_member(self, org_id: int, user_id: int, role: str = "analyst") -> None:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO org_members (org_id,user_id,role,joined_at) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (org_id,user_id) DO UPDATE SET role=EXCLUDED.role",
                (org_id, user_id, role, now)
            )
        else:
            c.execute(
                "INSERT OR REPLACE INTO org_members (org_id,user_id,role,joined_at) VALUES (?,?,?,?)",
                (org_id, user_id, role, now)
            )
        self.conn.commit()

    def get_user_organizations(self, user_id: int) -> list:
        c = self.conn.cursor()
        c.execute(self._q("""
            SELECT o.*, m.role AS my_role FROM organizations o
            JOIN org_members m ON m.org_id = o.id
            WHERE m.user_id = ? ORDER BY o.created_at ASC
        """), (user_id,))
        return [dict(r) for r in c.fetchall()]

    def get_organization(self, org_id: int):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM organizations WHERE id=?"), (org_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_org_role(self, org_id: int, user_id: int):
        c = self.conn.cursor()
        c.execute(self._q("SELECT role FROM org_members WHERE org_id=? AND user_id=?"), (org_id, user_id))
        row = c.fetchone()
        return row["role"] if row else None

    def get_org_members(self, org_id: int) -> list:
        c = self.conn.cursor()
        c.execute(self._q("""
            SELECT u.id, u.username, m.role, m.joined_at FROM org_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.org_id = ? ORDER BY m.joined_at ASC
        """), (org_id,))
        return [dict(r) for r in c.fetchall()]

    # ── ASSETS ───────────────────────────────────────────────────────────────

    def create_asset(self, org_id: int, name: str, asset_type: str, address: str, added_by: int = None) -> int:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO assets (org_id,name,asset_type,address,status,added_by,created_at) "
                "VALUES (%s,%s,%s,%s,'unknown',%s,%s) RETURNING id",
                (org_id, name, asset_type, address, added_by, now)
            )
            asset_id = c.fetchone()["id"]
        else:
            c.execute(
                "INSERT INTO assets (org_id,name,asset_type,address,status,added_by,created_at) "
                "VALUES (?,?,?,?,'unknown',?,?)",
                (org_id, name, asset_type, address, added_by, now)
            )
            asset_id = c.lastrowid
        self.conn.commit()
        return asset_id

    def get_assets(self, org_id: int) -> list:
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM assets WHERE org_id=? ORDER BY created_at DESC"), (org_id,))
        return [dict(r) for r in c.fetchall()]

    def get_asset(self, asset_id: int):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM assets WHERE id=?"), (asset_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def update_asset_status(self, asset_id: int, status: str) -> None:
        c = self.conn.cursor()
        c.execute(self._q("UPDATE assets SET status=? WHERE id=?"), (status, asset_id))
        self.conn.commit()

    def delete_asset(self, asset_id: int) -> None:
        c = self.conn.cursor()
        c.execute(self._q("DELETE FROM assets WHERE id=?"), (asset_id,))
        self.conn.commit()

    # ── SESSION METHODS ───────────────────────────────────────────────────────

    def create_session(self, target: str, org_id: int = None, asset_id: int = None) -> str:
        session_id = uuid.uuid4().hex[:8]
        c = self.conn.cursor()
        c.execute(self._q(
            "INSERT INTO sessions (id, target, started_at, status, org_id, asset_id) "
            "VALUES (?, ?, ?, 'running', ?, ?)"
        ), (session_id, target, datetime.now().isoformat(), org_id, asset_id))
        self.conn.commit()
        return session_id

    def complete_session(self, session_id: str):
        c = self.conn.cursor()
        c.execute(self._q(
            "UPDATE sessions SET status='completed', completed_at=? WHERE id=?"
        ), (datetime.now().isoformat(), session_id))
        self.conn.commit()

    def error_session(self, session_id: str):
        c = self.conn.cursor()
        c.execute(self._q(
            "UPDATE sessions SET status='error', completed_at=? WHERE id=?"
        ), (datetime.now().isoformat(), session_id))
        self.conn.commit()

    def get_session(self, session_id: str):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM sessions WHERE id=?"), (session_id,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_all_sessions(self, org_id: int = None) -> list:
        c = self.conn.cursor()
        # Exclude permanently deleted sessions
        deleted = self._get_deleted_ids()
        if org_id is None:
            c.execute("SELECT * FROM sessions ORDER BY started_at DESC")
        else:
            # Include legacy scans (org_id IS NULL, pre-dating this feature)
            # so upgraded installs don't lose visibility into old history.
            c.execute(self._q(
                "SELECT * FROM sessions WHERE org_id=? OR org_id IS NULL ORDER BY started_at DESC"
            ), (org_id,))
        rows = c.fetchall()
        return [dict(r) for r in rows if r["id"] not in deleted]

    def _get_deleted_ids(self) -> set:
        c = self.conn.cursor()
        c.execute("SELECT id FROM deleted_sessions")
        return {r["id"] for r in c.fetchall()}

    def delete_session(self, session_id: str):
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO deleted_sessions (id, deleted_at) VALUES (%s, %s) "
                "ON CONFLICT (id) DO NOTHING",
                (session_id, now)
            )
        else:
            c.execute(
                "INSERT OR IGNORE INTO deleted_sessions (id, deleted_at) VALUES (?, ?)",
                (session_id, now)
            )
        self.conn.commit()

    def fix_stale_sessions(self):
        """Mark sessions stuck in running for >30 min as error."""
        c = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(minutes=30)).isoformat()
        c.execute(self._q(
            "UPDATE sessions SET status='error' WHERE status='running' AND started_at < ?"
        ), (cutoff,))
        self.conn.commit()

    # ── HOST METHODS ──────────────────────────────────────────────────────────

    def save_hosts(self, session_id: str, hosts: list):
        c = self.conn.cursor()
        for host in hosts:
            if self._pg:
                c.execute(
                    "INSERT INTO hosts (session_id, ip, hostname, os, status) VALUES (%s,%s,%s,%s,%s) "
                    "RETURNING id",
                    (session_id, host.get("ip",""), host.get("hostname",""),
                     host.get("os","Unknown"), host.get("status","up"))
                )
                host_id = c.fetchone()["id"]
            else:
                c.execute(
                    "INSERT INTO hosts (session_id, ip, hostname, os, status) VALUES (?,?,?,?,?)",
                    (session_id, host.get("ip",""), host.get("hostname",""),
                     host.get("os","Unknown"), host.get("status","up"))
                )
                host_id = c.lastrowid

            for port in host.get("ports", []):
                c.execute(self._q(
                    "INSERT INTO ports (host_id, port, protocol, state, service, version) "
                    "VALUES (?,?,?,?,?,?)"
                ), (host_id, port.get("port"), port.get("protocol","tcp"),
                    port.get("state","open"), port.get("service",""),
                    str(port.get("version",""))[:200]))
        self.conn.commit()

    def get_hosts(self, session_id: str) -> list:
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM hosts WHERE session_id=?"), (session_id,))
        hosts = []
        for host in c.fetchall():
            host = dict(host)
            c2 = self.conn.cursor()
            c2.execute(self._q("SELECT * FROM ports WHERE host_id=?"), (host["id"],))
            host["ports"] = [dict(p) for p in c2.fetchall()]
            hosts.append(host)
        return hosts

    # ── FINDINGS METHODS ──────────────────────────────────────────────────────

    def save_web_findings(self, session_id: str, findings: list):
        c = self.conn.cursor()
        seen = set()
        for f in findings:
            key = (session_id, f.get("vuln_type",""), f.get("host_ip",""), f.get("url",""))
            if key in seen:
                continue
            seen.add(key)
            # Check not already in DB
            c.execute(self._q(
                "SELECT id FROM web_findings WHERE session_id=? AND vuln_type=? AND host_ip=? AND url=?"
            ), (session_id, f.get("vuln_type",""), f.get("host_ip",""), f.get("url","")))
            if c.fetchone():
                continue
            c.execute(self._q(
                "INSERT INTO web_findings "
                "(session_id, host_ip, url, vuln_type, severity, description, evidence, recommendation) "
                "VALUES (?,?,?,?,?,?,?,?)"
            ), (session_id, f.get("host_ip",""), f.get("url",""),
                f.get("vuln_type",""), f.get("severity","Low"),
                f.get("description",""), f.get("evidence",""),
                f.get("recommendation","")))
        self.conn.commit()

    def get_web_findings(self, session_id: str) -> list:
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM web_findings WHERE session_id=?"), (session_id,))
        return [dict(r) for r in c.fetchall()]

    def save_cve_findings(self, session_id: str, findings: list):
        c = self.conn.cursor()
        seen = set()
        for f in findings:
            key = (session_id, f.get("cve_id",""), f.get("host_ip",""))
            if key in seen:
                continue
            seen.add(key)
            c.execute(self._q(
                "SELECT id FROM cve_findings WHERE session_id=? AND cve_id=? AND host_ip=?"
            ), (session_id, f.get("cve_id",""), f.get("host_ip","")))
            if c.fetchone():
                continue
            c.execute(self._q(
                "INSERT INTO cve_findings "
                "(session_id, host_ip, port, service, cve_id, cvss_score, severity, description, reference) "
                "VALUES (?,?,?,?,?,?,?,?,?)"
            ), (session_id, f.get("host_ip",""), f.get("port",0),
                f.get("service",""), f.get("cve_id",""),
                f.get("cvss_score",0.0), f.get("severity","Low"),
                f.get("description",""), f.get("reference","")))
        self.conn.commit()

    def get_cve_findings(self, session_id: str) -> list:
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM cve_findings WHERE session_id=?"), (session_id,))
        return [dict(r) for r in c.fetchall()]

    # ── SEVERITY & STATS ──────────────────────────────────────────────────────

    def get_severity_counts(self, session_id: str = None) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        c = self.conn.cursor()
        for table in ("web_findings", "cve_findings"):
            if session_id:
                c.execute(self._q(f"SELECT severity, COUNT(*) as n FROM {table} WHERE session_id=? GROUP BY severity"), (session_id,))
            else:
                c.execute(f"SELECT severity, COUNT(*) as n FROM {table} GROUP BY severity")
            for row in c.fetchall():
                row = dict(row)
                sev = row.get("severity","")
                if sev in counts:
                    counts[sev] += row.get("n", 0)
        return counts

    def get_total_findings(self, session_id: str = None) -> int:
        counts = self.get_severity_counts(session_id)
        return sum(counts.values())

    # ── SCAN LOGS ─────────────────────────────────────────────────────────────

    def append_log(self, session_id: str, message: str):
        c = self.conn.cursor()
        c.execute(self._q(
            "INSERT INTO scan_logs (session_id, message, created_at) VALUES (?,?,?)"
        ), (session_id, message, datetime.now().isoformat()))
        self.conn.commit()

    def get_logs(self, session_id: str) -> list:
        c = self.conn.cursor()
        c.execute(self._q("SELECT message FROM scan_logs WHERE session_id=? ORDER BY id"), (session_id,))
        return [row["message"] for row in c.fetchall()]

    def set_scan_status(self, session_id: str, status: str, progress: int,
                        hosts_found: int = 0, web_count: int = 0,
                        cve_count: int = 0, report_paths: str = ""):
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO scan_status (session_id,status,progress,hosts_found,web_count,cve_count,report_paths,updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (session_id) DO UPDATE SET status=EXCLUDED.status, progress=EXCLUDED.progress, "
                "hosts_found=EXCLUDED.hosts_found, web_count=EXCLUDED.web_count, "
                "cve_count=EXCLUDED.cve_count, report_paths=EXCLUDED.report_paths, updated_at=EXCLUDED.updated_at",
                (session_id, status, progress, hosts_found, web_count, cve_count, report_paths, now)
            )
        else:
            c.execute(
                "INSERT OR REPLACE INTO scan_status "
                "(session_id,status,progress,hosts_found,web_count,cve_count,report_paths,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (session_id, status, progress, hosts_found, web_count, cve_count, report_paths, now)
            )
        self.conn.commit()

    def get_scan_status(self, session_id: str):
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM scan_status WHERE session_id=?"), (session_id,))
        row = c.fetchone()
        return dict(row) if row else None

    # ── NOTES ─────────────────────────────────────────────────────────────────

    def save_notes(self, session_id: str, notes: str):
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO scan_notes (session_id, notes, updated_at) VALUES (%s,%s,%s) "
                "ON CONFLICT (session_id) DO UPDATE SET notes=EXCLUDED.notes, updated_at=EXCLUDED.updated_at",
                (session_id, notes, now)
            )
        else:
            c.execute(
                "INSERT OR REPLACE INTO scan_notes (session_id, notes, updated_at) VALUES (?,?,?)",
                (session_id, notes, now)
            )
        self.conn.commit()

    def get_notes(self, session_id: str) -> str:
        c = self.conn.cursor()
        c.execute(self._q("SELECT notes FROM scan_notes WHERE session_id=?"), (session_id,))
        row = c.fetchone()
        return row["notes"] if row else ""

    # ── SCHEDULES ─────────────────────────────────────────────────────────────

    def get_schedules(self) -> list:
        c = self.conn.cursor()
        c.execute("SELECT * FROM scan_schedules WHERE active=1 ORDER BY next_run")
        return [dict(r) for r in c.fetchall()]

    def add_schedule(self, target: str, scan_type: str, port_range: str,
                     frequency: str, next_run: str) -> int:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO scan_schedules (target,scan_type,port_range,frequency,next_run,active,created_at) "
                "VALUES (%s,%s,%s,%s,%s,1,%s) RETURNING id",
                (target, scan_type, port_range, frequency, next_run, now)
            )
            return c.fetchone()["id"]
        else:
            c.execute(
                "INSERT INTO scan_schedules (target,scan_type,port_range,frequency,next_run,active,created_at) "
                "VALUES (?,?,?,?,?,1,?)",
                (target, scan_type, port_range, frequency, next_run, now)
            )
            self.conn.commit()
            return c.lastrowid

    def update_schedule_run(self, schedule_id: int):
        c = self.conn.cursor()
        c.execute(self._q("SELECT frequency FROM scan_schedules WHERE id=?"), (schedule_id,))
        row = c.fetchone()
        if not row:
            return
        freq_map = {"hourly": 1, "daily": 24, "weekly": 168}
        hours    = freq_map.get(row["frequency"], 24)
        next_run = (datetime.now() + timedelta(hours=hours)).isoformat()
        c.execute(self._q(
            "UPDATE scan_schedules SET last_run=?, next_run=? WHERE id=?"
        ), (datetime.now().isoformat(), next_run, schedule_id))
        self.conn.commit()

    def delete_schedule(self, schedule_id: int):
        c = self.conn.cursor()
        c.execute(self._q("UPDATE scan_schedules SET active=0 WHERE id=?"), (schedule_id,))
        self.conn.commit()

    def get_due_schedules(self) -> list:
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        c.execute(self._q(
            "SELECT * FROM scan_schedules WHERE active=1 AND next_run <= ?"
        ), (now,))
        return [dict(r) for r in c.fetchall()]



    # ── PERSISTENT REPORT STORAGE (survives Render redeploys) ──────────────────

    def _init_reports_table(self):
        c = self.conn.cursor()
        if self._pg:
            c.execute("""
                CREATE TABLE IF NOT EXISTS report_files (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    file_data BYTEA NOT NULL,
                    file_size INTEGER,
                    created_at TEXT NOT NULL
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS report_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    file_data BLOB NOT NULL,
                    file_size INTEGER,
                    created_at TEXT NOT NULL
                )
            """)
        self.conn.commit()

    def save_report_file(self, session_id, target, filename, file_type, file_bytes):
        self._init_reports_table()
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO report_files (session_id, target, filename, file_type, file_data, file_size, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (session_id, target, filename, file_type, psycopg2.Binary(file_bytes), len(file_bytes), now)
            )
        else:
            c.execute(
                "INSERT INTO report_files (session_id, target, filename, file_type, file_data, file_size, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (session_id, target, filename, file_type, file_bytes, len(file_bytes), now)
            )
        self.conn.commit()

    def get_report_file(self, filename):
        self._init_reports_table()
        c = self.conn.cursor()
        c.execute(self._q("SELECT * FROM report_files WHERE filename=?"), (filename,))
        row = c.fetchone()
        if not row:
            return None
        row = dict(row)
        if self._pg:
            row["file_data"] = bytes(row["file_data"])
        return row

    def get_all_report_files(self):
        self._init_reports_table()
        c = self.conn.cursor()
        c.execute("SELECT id, session_id, target, filename, file_type, file_size, created_at FROM report_files ORDER BY created_at DESC")
        return [dict(r) for r in c.fetchall()]

    def get_reports_for_session(self, session_id):
        self._init_reports_table()
        c = self.conn.cursor()
        c.execute(self._q("SELECT id, session_id, target, filename, file_type, file_size, created_at FROM report_files WHERE session_id=? ORDER BY created_at DESC"), (session_id,))
        return [dict(r) for r in c.fetchall()]

    def delete_report_file(self, filename):
        """Permanently delete a report file from the database."""
        self._init_reports_table()
        c = self.conn.cursor()
        c.execute(self._q("DELETE FROM report_files WHERE filename=?"), (filename,))
        self.conn.commit()
        return c.rowcount > 0

    def delete_session_permanently(self, session_id):
        """Permanently delete a scan session and ALL associated data — no recovery."""
        c = self.conn.cursor()
        tables = ["hosts", "ports", "web_findings", "cve_findings",
                  "scan_logs", "scan_status", "scan_notes", "report_files"]
        # ports references host_id, need to delete via host lookup first
        c.execute(self._q("SELECT id FROM hosts WHERE session_id=?"), (session_id,))
        host_ids = [r["id"] for r in c.fetchall()]
        for hid in host_ids:
            c.execute(self._q("DELETE FROM ports WHERE host_id=?"), (hid,))
        for t in ["hosts", "web_findings", "cve_findings", "scan_logs",
                  "scan_status", "scan_notes", "report_files"]:
            c.execute(self._q(f"DELETE FROM {t} WHERE session_id=?"), (session_id,))
        c.execute(self._q("DELETE FROM sessions WHERE id=?"), (session_id,))
        self.conn.commit()
        return True


    def _init_screenshots_table(self):
        c = self.conn.cursor()
        if self._pg:
            c.execute("""
                CREATE TABLE IF NOT EXISTS screenshots (
                    session_id TEXT PRIMARY KEY,
                    image_data BYTEA NOT NULL,
                    captured_at TEXT NOT NULL
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS screenshots (
                    session_id TEXT PRIMARY KEY,
                    image_data BLOB NOT NULL,
                    captured_at TEXT NOT NULL
                )
            """)
        self.conn.commit()

    def save_screenshot(self, session_id, image_bytes):
        self._init_screenshots_table()
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        if self._pg:
            c.execute(
                "INSERT INTO screenshots (session_id, image_data, captured_at) "
                "VALUES (%s, %s, %s) ON CONFLICT (session_id) DO UPDATE "
                "SET image_data=EXCLUDED.image_data, captured_at=EXCLUDED.captured_at",
                (session_id, psycopg2.Binary(image_bytes), now)
            )
        else:
            c.execute(
                "INSERT OR REPLACE INTO screenshots (session_id, image_data, captured_at) "
                "VALUES (?,?,?)",
                (session_id, image_bytes, now)
            )
        self.conn.commit()

    def get_screenshot(self, session_id):
        self._init_screenshots_table()
        c = self.conn.cursor()
        c.execute(self._q("SELECT image_data FROM screenshots WHERE session_id=?"), (session_id,))
        row = c.fetchone()
        if not row:
            return None
        data = row["image_data"] if isinstance(row, dict) else row[0]
        return bytes(data) if data else None

    # ── CLOSE ─────────────────────────────────────────────────────────────────

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
