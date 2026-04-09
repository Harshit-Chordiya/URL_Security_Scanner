import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import logging
from typing import List, Callable, Optional

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0; +https://url-security-scanner.onrender.com)"
}


class WebCrawler:
    def __init__(self, base_url: str, max_pages: int = 30, delay: float = 1.0):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.visited: set = set()
        self.pages: List[dict] = []

    def _normalize_url(self, url: str) -> Optional[str]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        if parsed.netloc != self.base_domain:
            return None
        # Strip fragments
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        return clean

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all("a", href=True):
            full = urljoin(base_url, tag["href"])
            normalized = self._normalize_url(full)
            if normalized and normalized not in self.visited:
                links.append(normalized)
        return links

    def crawl(self, progress_callback: Callable = None) -> List[dict]:
        queue = [self.base_url]

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                resp = self.session.get(url, timeout=50, allow_redirects=True)

                # Parse Set-Cookie headers for security attribute analysis
                raw_cookies = []
                for raw in resp.raw.headers.getlist("Set-Cookie"):
                    raw_cookies.append(raw)

                page = {
                    "url": url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "raw_cookies": raw_cookies,
                    "content": resp.text,
                    "content_type": resp.headers.get("Content-Type", ""),
                }
                self.pages.append(page)

                if progress_callback:
                    progress_callback(
                        f"Crawled [{resp.status_code}] {url}  ({len(self.visited)}/{self.max_pages} pages)"
                    )

                if "text/html" in page["content_type"]:
                    for link in self._extract_links(url, resp.text):
                        if link not in self.visited:
                            queue.append(link)

            except requests.exceptions.SSLError as e:
                if progress_callback:
                    progress_callback(f"SSL error on {url}: {e}")
                self.pages.append({
                    "url": url, "final_url": url, "status_code": 0,
                    "headers": {}, "raw_cookies": [], "content": "",
                    "content_type": "", "error": f"SSL: {e}"
                })
            except Exception as e:
                logger.warning(f"Error crawling {url}: {e}")
                if progress_callback:
                    progress_callback(f"Error on {url}: {e}")

            time.sleep(self.delay)

        return self.pages
