"""
CyberScan Pro — Authentication Module
Handles login, registration, logout, and login_required decorator.
Backed by real user + organization records (see modules/database.py).
Includes rate limiting: max 5 failed attempts per 15 minutes per IP.
"""

import os
import time
from collections import defaultdict
from functools import wraps
from flask import (
    Blueprint, render_template, request, session,
    redirect, url_for, jsonify, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

from modules.database import Database

auth = Blueprint("auth", __name__)

# ── Rate limiter state ─────────────────────────────────────────────────────────
_attempts: dict = defaultdict(list)
MAX_ATTEMPTS   = 5
WINDOW_SECONDS = 15 * 60   # 15 minutes
LOCKOUT_SECONDS = 15 * 60  # same window


def _get_ip() -> str:
    """Get the real client IP, respecting X-Forwarded-For from Render's proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_locked_out(ip: str) -> tuple[bool, int]:
    """Return (is_locked, seconds_remaining)."""
    now = time.time()
    recent = [t for t in _attempts[ip] if now - t < WINDOW_SECONDS]
    _attempts[ip] = recent
    if len(recent) >= MAX_ATTEMPTS:
        oldest = min(recent)
        remaining = int(WINDOW_SECONDS - (now - oldest))
        return True, max(0, remaining)
    return False, 0


def _record_failure(ip: str) -> None:
    _attempts[ip].append(time.time())


def _clear_failures(ip: str) -> None:
    _attempts.pop(ip, None)


def _bootstrap_default_account() -> None:
    """First-run only: create the admin user (from env vars) + their
    default organization, so existing installs keep working with zero
    extra setup after upgrading to the organizations/assets model."""
    db = Database()
    try:
        valid_user = os.environ.get("NETSCAN_USER", "admin")
        valid_pass = os.environ.get("NETSCAN_PASS", "admin123")
        db.ensure_default_user_and_org(valid_user, generate_password_hash(valid_pass))
    finally:
        db.close()


def _establish_session(user: dict) -> None:
    """Populate the Flask session for a logged-in user: identity + their
    organization context (first org they belong to, for now)."""
    db = Database()
    try:
        orgs = db.get_user_organizations(user["id"])
    finally:
        db.close()
    session.clear()
    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    session["last_active"] = time.time()
    session.permanent = True
    if orgs:
        session["org_id"]   = orgs[0]["id"]
        session["org_name"] = orgs[0]["name"]
        session["org_role"] = orgs[0]["my_role"]


# ── login_required decorator ───────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def org_role_required(*roles):
    """Restrict a route to specific organization roles (e.g. 'owner').
    Must be used underneath @login_required."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("org_role") not in roles:
                return jsonify({"error": "You don't have permission to do that."}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper


# ── Login route ────────────────────────────────────────────────────────────────

@auth.route("/login", methods=["GET", "POST"])
def login():
    _bootstrap_default_account()

    error    = None
    locked   = False
    wait_sec = 0

    if request.method == "POST":
        ip = _get_ip()
        is_locked, wait_sec = _is_locked_out(ip)

        if is_locked:
            locked = True
            wait_min = wait_sec // 60 + 1
            error = (
                f"Too many failed attempts. "
                f"Try again in {wait_min} minute{'s' if wait_min != 1 else ''}."
            )
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            db = Database()
            try:
                user = db.get_user_by_username(username)
            finally:
                db.close()

            if user and check_password_hash(user["password_hash"], password):
                _clear_failures(ip)
                _establish_session(user)

                next_url = request.args.get("next", "")
                # Safety: only allow relative redirects
                if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                    return redirect(next_url)
                return redirect(url_for("index"))
            else:
                _record_failure(ip)
                remaining_tries = MAX_ATTEMPTS - len(_attempts[ip])
                if remaining_tries > 0:
                    error = (
                        f"Invalid username or password. "
                        f"{remaining_tries} attempt{'s' if remaining_tries != 1 else ''} remaining."
                    )
                else:
                    locked = True
                    error  = "Too many failed attempts. Locked for 15 minutes."

    return render_template(
        "login.html",
        error=error,
        locked=locked,
        wait_sec=wait_sec,
    )


# ── Register route ────────────────────────────────────────────────────────────
# Real-world flow: a security team signs up, gets their own Organization,
# then registers assets under it. Every scan they run is scoped to that org.

@auth.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        org_name = request.form.get("org_name", "").strip()

        if len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif not org_name:
            error = "Organization name is required."
        else:
            db = Database()
            try:
                if db.get_user_by_username(username):
                    error = "That username is already taken."
                else:
                    user_id = db.create_user(username, generate_password_hash(password))
                    db.create_organization(org_name, user_id)
                    user = db.get_user_by_id(user_id)
                    _establish_session(user)
                    db.close()
                    return redirect(url_for("index"))
            finally:
                db.close()

    return render_template("register.html", error=error)


# ── Logout route ───────────────────────────────────────────────────────────────

@auth.route("/logout")
def logout():
    ip = _get_ip()
    _clear_failures(ip)
    session.clear()
    return redirect(url_for("auth.login"))
