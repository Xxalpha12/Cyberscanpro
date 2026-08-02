"""
CyberScan Pro — Authentication Module
Handles login, logout, and login_required decorator.
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


# ── login_required decorator ───────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


# ── Login route ────────────────────────────────────────────────────────────────

@auth.route("/login", methods=["GET", "POST"])
def login():
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

            valid_user = os.environ.get("NETSCAN_USER", "admin")
            valid_pass = os.environ.get("NETSCAN_PASS", "admin123")

            if username == valid_user and password == valid_pass:
                _clear_failures(ip)
                session.clear()
                session["username"]    = username
                session["last_active"] = time.time()
                session.permanent      = True

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


# ── Logout route ───────────────────────────────────────────────────────────────

@auth.route("/logout")
def logout():
    ip = _get_ip()
    _clear_failures(ip)
    session.clear()
    return redirect(url_for("auth.login"))
