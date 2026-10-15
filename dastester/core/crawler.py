"""A polite, scope-bounded crawler that discovers pages and parameters.

The crawler collects the surface DASTester will test: reachable URLs plus
the query parameters and forms observed on each page. It honours scope,
depth, and page caps, and does not follow links outside scope.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs, urldefrag

from bs4 import BeautifulSoup

from .config import ScanConfig
from .http_client import HttpClient


@dataclass
class PageInfo:
    url: str
    status: int
    headers: dict
    body: str
    params: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[dict] = field(default_factory=list)


class Crawler:
    def __init__(self, config: ScanConfig, http: HttpClient, logger=None):
        self.config = config
        self.http = http
        self.log = logger

    def _emit(self, msg):
        if self.log:
            self.log(msg)

    def crawl(self) -> Dict[str, PageInfo]:
        visited: Dict[str, PageInfo] = {}
        seen: Set[str] = set()
        queue = deque()
        for t in self.config.targets:
            url = urldefrag(t)[0]
            queue.append((url, 0))
            seen.add(url)

        while queue and len(visited) < self.config.max_pages:
            url, depth = queue.popleft()
            if not self.config.in_scope(url):
                continue
            resp = self.http.get(url)
            if resp is None:
                continue
            page = self._parse(url, resp)
            visited[page.url] = page
            self._emit(f"crawled [{resp.status}] {page.url}")

            if depth >= self.config.max_depth:
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype:
                continue
            for link in self._extract_links(page.url, resp.text):
                link = urldefrag(link)[0]
                if link in seen:
                    continue
                if not self.config.in_scope(link):
                    continue
                seen.add(link)
                queue.append((link, depth + 1))
        return visited

    def _parse(self, url: str, resp) -> PageInfo:
        params = {k: v for k, v in parse_qs(urlparse(url).query).items()}
        forms = []
        if "html" in resp.headers.get("Content-Type", ""):
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form"):
                    action = urljoin(url, form.get("action") or url)
                    method = (form.get("method") or "get").lower()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({
                                "name": name,
                                "type": inp.get("type", "text"),
                            })
                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                    })
            except Exception:
                pass
        return PageInfo(
            url=resp.final_url or url,
            status=resp.status,
            headers=resp.headers,
            body=resp.text,
            params=params,
            forms=forms,
        )

    def _extract_links(self, base: str, html: str) -> List[str]:
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return links
        for tag, attr in (("a", "href"), ("link", "href"), ("script", "src"),
                          ("form", "action")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val:
                    continue
                if val.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                links.append(urljoin(base, val))
        return links
