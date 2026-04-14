"""
NetScan Pro - Scan Scheduler Module
Allows scheduling recurring scans at set intervals.
Schedules are stored in the database and checked on dashboard load.
"""

import threading
import time
from datetime import datetime, timedelta
from modules.logger import get_logger

logger = get_logger(__name__)


class ScanScheduler:
    """
    Manages scheduled scans. Runs a background thread that checks
    every minute for due scans and triggers them automatically.
    """

    def __init__(self, db, trigger_scan_fn):
        self.db             = db
        self.trigger_scan   = trigger_scan_fn  # function to call to start a scan
        self._running       = False
        self._thread        = None

    def start(self):
        """Start the scheduler background thread."""
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Scan scheduler started.")

    def stop(self):
        self._running = False

    def _loop(self):
        """Check for due schedules every 60 seconds."""
        while self._running:
            try:
                self._check_schedules()
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
            time.sleep(60)

    def _check_schedules(self):
        from modules.database import Database
        db = Database()
        schedules = db.get_due_schedules()
        for sched in schedules:
            logger.info(f"Triggering scheduled scan: {sched['target']}")
            try:
                self.trigger_scan(sched["target"], sched.get("scan_type","quick"),
                                  sched.get("port_range","1-1024"))
                db.update_schedule_last_run(sched["id"])
            except Exception as e:
                logger.error(f"Scheduled scan failed: {e}")
        db.close()
