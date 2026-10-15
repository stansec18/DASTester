"""A thin, rate-limited HTTP client used by all checks.

Centralising requests here lets DASTester enforce the rate limit, scope,
timeout, and a consistent User-Agent in one place, and keeps checks
non-destructive by using GET/HEAD by default.
"""

from __future__ import annotations

import time
import threading
import warnings
from dataclasses import dataclass
from typing import Optional

import requests
import urllib3

from .config import ScanConfig


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    text: str
    elapsed: float
    final_url: str
    history_len: int


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class HttpClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.limiter = RateLimiter(config.rate_limit)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.session.headers.update(config.headers or {})
        if config.cookies:
            self.session.cookies.update(config.cookies)
        if not config.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        # Hard scope guard: never send a request outside scope.
        if not self.config.in_scope(url):
            return None
        self.limiter.wait()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.config.verify_tls)
        attempts = self.config.max_retries + 1
        last_exc = None
        for _ in range(attempts):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    r = self.session.request(method, url, **kwargs)
                return Response(
                    url=url,
                    status=r.status_code,
                    headers=dict(r.headers),
                    text=r.text if "text" in r.headers.get("Content-Type", "")
                    or "html" in r.headers.get("Content-Type", "")
                    or "json" in r.headers.get("Content-Type", "")
                    or not r.headers.get("Content-Type")
                    else "",
                    elapsed=r.elapsed.total_seconds(),
                    final_url=r.url,
                    history_len=len(r.history),
                )
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(0.2)
        self.last_error = last_exc
        return None

    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[Response]:
        return self.request("HEAD", url, **kwargs)
