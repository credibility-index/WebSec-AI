import re
import requests
from typing import List, Set
from urllib.parse import urljoin, urlparse

def extract_links(base_url: str, html: str, same_origin_only: bool = True) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    try:
        parsed_base = urlparse(base_url)
        host = parsed_base.netloc.lower()
        scheme = parsed_base.scheme or "https"

        for m in re.finditer(r'href\s*=\s*["\']([^"\']+)["\']', html, re.I):
            href = m.group(1).strip().split("#")[0].strip()
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = urljoin(base_url, href)
            p = urlparse(full)
            if same_origin_only and p.netloc.lower() != host:
                continue
            if p.scheme not in ("http", "https"):
                continue
            if full not in seen:
                seen.add(full)
                result.append(full)
    except Exception:
        pass
    return result


def crawl_urls(start_url: str, max_pages: int = 20, timeout: int = 8) -> List[str]:
    urls: List[str] = []
    seen: Set[str] = set()
    queue: List[str] = [start_url]
    try:
        while queue and len(urls) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                resp.raise_for_status()
                links = extract_links(url, resp.text or "", same_origin_only=True)
                for link in links:
                    if link not in seen and len(urls) + len(queue) < max_pages:
                        queue.append(link)
            except requests.RequestException:
                pass
            except Exception:
                pass
    except Exception:
        pass
    return urls[:max_pages]
