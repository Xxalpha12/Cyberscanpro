"""
CyberScan Pro - Visual Screenshot Capture Module
Uses screenshotone.com API for real browser screenshots.
Falls back to text preview if API key not set.
"""

import os
import requests
from modules.logger import get_logger

logger = get_logger(__name__)

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "output", "screenshots"
)
requests.packages.urllib3.disable_warnings()


class ScreenshotCapture:

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.api_key = os.environ.get("SCREENSHOT_API_KEY", "")
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def capture(self, url: str, session_id: str) -> str | None:
        """Capture screenshot. Returns path to saved image or None."""
        if not url.startswith("http"):
            url = f"http://{url}"

        filepath = os.path.join(OUTPUT_DIR, f"screenshot_{session_id}.png")

        # Method 1: screenshotone.com (real browser screenshot)
        if self.api_key:
            result = self._screenshotone(url, filepath)
            if result:
                return result

        # Method 2: thum.io (free, no key needed)
        result = self._thumio(url, filepath)
        if result:
            return result

        # Method 3: Text preview fallback
        return self._text_preview(url, filepath)

    def _screenshotone(self, url: str, filepath: str) -> str | None:
        """Real browser screenshot via screenshotone.com."""
        try:
            api_url = "https://api.screenshotone.com/take"
            params = {
                "access_key":        self.api_key,
                "url":               url,
                "viewport_width":    1280,
                "viewport_height":   800,
                "format":            "png",
                "block_ads":         "true",
                "block_cookie_banners": "true",
                "delay":             2,
                "timeout":           30,
            }
            r = requests.get(api_url, params=params, timeout=self.timeout)
            if r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                with open(filepath, "wb") as f:
                    f.write(r.content)
                logger.info(f"Visual screenshot saved: {filepath}")
                return filepath
            else:
                logger.warning(f"screenshotone API error: {r.status_code} {r.text[:100]}")
        except Exception as e:
            logger.warning(f"screenshotone failed: {e}")
        return None

    def _thumio(self, url: str, filepath: str) -> str | None:
        """Free screenshot via thum.io."""
        try:
            import urllib.parse
            encoded = urllib.parse.quote(url, safe="")
            api_url  = f"https://image.thum.io/get/width/1280/crop/800/{encoded}"
            r = requests.get(api_url, timeout=self.timeout, verify=False)
            if r.status_code == 200 and len(r.content) > 5000:
                with open(filepath, "wb") as f:
                    f.write(r.content)
                logger.info(f"Screenshot saved via thum.io: {filepath}")
                return filepath
        except Exception as e:
            logger.warning(f"thum.io failed: {e}")
        return None

    def _text_preview(self, url: str, filepath: str) -> str | None:
        """Generate text-based preview when screenshot APIs fail."""
        try:
            from PIL import Image, ImageDraw
            import re

            r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
            server  = r.headers.get("Server", "Unknown")
            powered = r.headers.get("X-Powered-By", "Not disclosed")
            status  = r.status_code
            title   = ""

            match = re.search(rb"<title>(.*?)</title>", r.content, re.IGNORECASE)
            if match:
                title = match.group(1).decode("utf-8", errors="ignore").strip()[:60]

            img  = Image.new("RGB", (1280, 800), color=(8, 12, 20))
            draw = ImageDraw.Draw(img)

            # Browser chrome bar
            draw.rectangle([0, 0, 1280, 50], fill=(0, 40, 60))
            draw.rectangle([0, 48, 1280, 50], fill=(0, 200, 255))
            draw.rectangle([10, 10, 1270, 38], fill=(10, 20, 35),
                           outline=(0, 200, 255))

            # URL in bar
            draw.text((20, 16), f"  {url}", fill=(0, 200, 255))

            # Status dot
            dot_color = (0, 200, 100) if status == 200 else (255, 100, 50)
            draw.ellipse([1240, 16, 1260, 36], fill=dot_color)

            # Content
            lines = [
                (f"HTTP Status:     {status}", (0, 200, 255)),
                (f"Server:          {server}", (160, 220, 240)),
                (f"Powered By:      {powered}", (160, 220, 240)),
                (f"Page Title:      {title or 'No title found'}", (160, 220, 240)),
                ("", None),
                (f"Content-Type:    {r.headers.get('Content-Type', 'Unknown')}", (100, 160, 190)),
                (f"Content-Length:  {r.headers.get('Content-Length', 'Unknown')}", (100, 160, 190)),
                ("", None),
                ("Security Headers:", (0, 200, 255)),
                (f"  X-Frame-Options:       {r.headers.get('X-Frame-Options', '⚠ MISSING')}", (200, 180, 100)),
                (f"  Content-Security-Policy: {r.headers.get('Content-Security-Policy', '⚠ MISSING')[:40]}", (200, 180, 100)),
                (f"  Strict-Transport-Security: {r.headers.get('Strict-Transport-Security', '⚠ MISSING')}", (200, 180, 100)),
            ]

            y = 80
            for text, color in lines:
                if color:
                    draw.text((60, y), text, fill=color)
                y += 40

            draw.text((20, 770),
                      "CyberScan Pro — Automated Vulnerability Assessment",
                      fill=(30, 60, 80))

            img.save(filepath, format="PNG")
            logger.info(f"Text preview generated: {filepath}")
            return filepath

        except Exception as e:
            logger.warning(f"Text preview failed: {e}")
        return None

    @staticmethod
    def get_screenshot_url(session_id: str) -> str:
        return f"/screenshots/{session_id}"
