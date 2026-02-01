import base64
import binascii
import re
import codecs
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

_FALSE_POSITIVE_FLAGS = frozenset({
    "getElementsByTagName", "getElementById", "getElementsByClassName",
    "addIntegrationMiddleware", "addDestinationMiddleware", "getAttribute",
    "setAttribute", "querySelector", "querySelectorAll", "createElement",
    "appendChild", "removeChild", "addEventListener", "dispatchEvent",
    "getBoundingClientRect", "requestAnimationFrame", "getContext",
    "toDataURL", "createObjectURL", "fetch", "then", "catch", "finally",
})


def _is_likely_false_positive(val: str) -> bool:
    if not val or len(val) < 10:
        return True
    if "/" in val or "uploads" in val.lower() or val.startswith("com/"):
        return True
    if val in _FALSE_POSITIVE_FLAGS:
        return True
    if re.match(r"^[a-fA-F0-9]{8,16}$", val):
        return True
    if re.match(r"^[A-Z][A-Z0-9_]{8,80}$", val) and "_" in val:
        return True
    if re.match(r"^[a-zA-Z_]+$", val) and len(val) <= 45 and re.search(r"[a-z][A-Z]|[A-Z][a-z]", val):
        return True
    return False


DEFAULT_PATTERNS = [
    r"flag\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"RACTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"Flag\{[^}]+\}",
    r"duckerz\{[^}]+\}",
    r"Duckerz\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"PicoCTF\{[^}]+\}",
    r"SECCON\{[^}]+\}",
    r"0ctf\{[^}]+\}",
    r"HITCON\{[^}]+\}",
    r"key\{[^}]+\}",
    r"KEY\{[^}]+\}",
    r"secret\{[^}]+\}",
    r"SECRET\{[^}]+\}",
    r"pass\{[^}]+\}",
    r"token\{[^}]+\}",
    r"FLAG_[A-Za-z0-9_]{10,50}",
    r"flag_[a-z0-9_]{10,50}",
    r"CTF_[A-Za-z0-9_]{10,50}",
    r"flag\([^)]+\)",
    r"ctf\([^)]+\)",
    r"duckerz\([^)]+\)",
    r"HTB\([^)]+\)",
    r"THM\([^)]+\)",
    r"flag\[[^]]+\]",
    r"ctf\[[^]]+\]",
    r"FLAG\[[^]]+\]",
    r"key\[[^]]+\]",
    r"secret\[[^]]+\]",
    r"flag\<[^>]+\>",
    r"ctf\<[^>]+\>",
    r"FLAG\<[^>]+\>",
    r"[a-zA-Z0-9_]{3,30}\s*[{\[<][^})\]>]+[})\]>]",
    r"FLAG-[A-Za-z0-9_-]{10,60}",
    r"flag-[a-z0-9_-]{10,60}",
    r"CTF-[A-Za-z0-9_-]{10,60}",
    r"[A-Za-z0-9+/]{24,80}={0,2}",
    r"[a-fA-F0-9]{32,64}",
]


def _get_patterns() -> List[str]:
    try:
        from core.config import get_flag_patterns
        return get_flag_patterns() or DEFAULT_PATTERNS
    except Exception:
        return DEFAULT_PATTERNS


def _decode_base64(s: str) -> Optional[str]:
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_hex(s: str) -> Optional[str]:
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s) % 2:
        return None
    try:
        return binascii.unhexlify(s).decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_rot13(s: str) -> str:
    return codecs.decode(s, "rot_13")


def _search_text(text: str, location: str, patterns: List[str]) -> List[Dict[str, Any]]:
    found = []
    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            val = m.group(0)
            if len(val) < 8 and "{" not in val and "}" not in val and "(" not in val and ")" not in val:
                continue
            if _is_likely_false_positive(val):
                continue
            found.append({
                "location": location,
                "flag": val,
                "method": "regex",
            })
    return found


def _search_and_decode(text: str, location: str, patterns: List[str]) -> List[Dict[str, Any]]:
    results = _search_text(text, location, patterns)
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for cand in b64_candidates[:20]:
        decoded = _decode_base64(cand)
        if decoded:
            decoded = decoded.strip()
            if re.search(r"flag|ctf|duckerz|\{[^}]+\}|\([^)]+\)", decoded, re.I) and not _is_likely_false_positive(decoded[:80]):
                results.append({
                    "location": location,
                    "flag": decoded,
                    "method": "base64_decode",
                    "raw": cand[:50],
                })
    hex_candidates = re.findall(r"[a-fA-F0-9]{32,}", text)
    for cand in hex_candidates[:15]:
        decoded = _decode_hex(cand)
        if decoded:
            decoded = decoded.strip()
            if (decoded.isprintable() or re.search(r"flag|ctf|\{[^}]+\}", decoded, re.I)) and not _is_likely_false_positive(decoded[:80]):
                results.append({
                    "location": location,
                    "flag": decoded,
                    "method": "hex_decode",
                    "raw": cand[:50],
                })
    return results


def _fetch_url(url: str, timeout: int = 10, session: Optional[requests.Session] = None) -> Optional[requests.Response]:
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", "WebSecAI-FlagHunter/1.0")
    try:
        return sess.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


RECON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.env",
    "/.env.backup",
    "/config.php.bak",
    "/.svn/entries",
    "/backup.sql",
    "/flag.txt",
    "/flag",
    "/secret.txt",
    "/.well-known/security.txt",
]


def _check_recon_paths(base_url: str, session: requests.Session, patterns: List[str], all_found: List[Dict[str, Any]], timeout: int) -> None:
    """Fetch robots.txt, sitemap.xml, .git/config, .env, backup paths and search for flags."""
    parsed = urlparse(base_url)
    base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    for path in RECON_PATHS:
        if len(all_found) > 200:
            break
        url = base.rstrip("/") + path
        resp = _fetch_url(url, timeout, session)
        if not resp or resp.status_code != 200:
            continue
        loc = f"{url} (response)"
        text = resp.text[:50000]
        found = _search_and_decode(text, loc, patterns)
        for f in found:
            f["location"] = loc
        all_found.extend(found)
        if "robots.txt" in path and "Disallow:" in text:
            for line in text.split("\n"):
                if line.strip().lower().startswith("disallow:"):
                    sub = line.split(":", 1)[1].strip().split("#")[0].strip()
                    if sub and sub != "/":
                        sub_url = base.rstrip("/") + (sub if sub.startswith("/") else "/" + sub)
                        sub_resp = _fetch_url(sub_url, timeout, session)
                        if sub_resp and sub_resp.status_code == 200:
                            sub_found = _search_and_decode(sub_resp.text[:30000], sub_url, patterns)
                            for s in sub_found:
                                s["location"] = sub_url
                            all_found.extend(sub_found)


def ai_decode_suggestion(cipher_sample: str, encoding_hint: Optional[str] = None) -> Optional[str]:
    """Ask AI for decode hint. Optional dependency on core.ai_engine."""
    try:
        from core.ai_engine import ai_decode_hint
        return ai_decode_hint(cipher_sample[:500], encoding_hint)
    except Exception:
        return None


def hunt_flags(
    base_url: str,
    max_pages: int = 15,
    timeout: int = 10,
    custom_patterns: Optional[List[str]] = None,
    check_robots_sitemap_git: bool = True,
) -> List[Dict[str, Any]]:
    patterns = custom_patterns or _get_patterns()
    all_found: List[Dict[str, Any]] = []
    seen_urls: set = set()
    session = requests.Session()
    session.headers["User-Agent"] = "WebSecAI-FlagHunter/1.0"

    if check_robots_sitemap_git:
        _check_recon_paths(base_url, session, patterns, all_found, timeout)

    def process_page(url: str, depth: int = 0) -> None:
        if depth > 2 or len(seen_urls) >= max_pages:
            return
        if url in seen_urls:
            return
        seen_urls.add(url)
        resp = _fetch_url(url, timeout, session)
        if not resp or resp.status_code != 200:
            return

        loc_prefix = url[:80] + ("..." if len(url) > 80 else "")

        for name, value in resp.headers.items():
            found = _search_and_decode(value, f"Header: {name}", patterns)
            for f in found:
                f["location"] = f"{loc_prefix} | {f['location']}"
            all_found.extend(found)

        for c in resp.cookies:
            found = _search_and_decode(str(c.value), f"Cookie: {c.name}", patterns)
            for f in found:
                f["location"] = f"{loc_prefix} | {f['location']}"
            all_found.extend(found)

        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            all_found.extend(_search_and_decode(resp.text[:50000], f"{loc_prefix} body", patterns))
            return

        soup = BeautifulSoup(resp.text, "lxml")
        if not soup:
            soup = BeautifulSoup(resp.text, "html.parser")

        from bs4 import Comment
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            found = _search_and_decode(str(comment), f"{loc_prefix} HTML comment", patterns)
            for f in found:
                f["location"] = f"{loc_prefix} | HTML comment"
            all_found.extend(found)

        body = soup.find("body") or soup
        text = body.get_text() if body else resp.text
        found = _search_and_decode(text[:100000], f"{loc_prefix} body", patterns)
        for f in found:
            f["location"] = f"{loc_prefix} | body"
        all_found.extend(found)

        for i, script in enumerate(soup.find_all("script")):
            if script.string:
                found = _search_and_decode(script.string, f"{loc_prefix} script[{i}]", patterns)
                for f in found:
                    f["location"] = f"{loc_prefix} | script"
                all_found.extend(found)

        for tag in soup.find_all(["script", "link"], src=True) or soup.find_all("script") or []:
            src = tag.get("src") or tag.get("href")
            if not src or not (src.endswith(".js") or "javascript" in src):
                continue
            js_url = urljoin(url, src)
            if js_url in seen_urls:
                continue
            js_resp = _fetch_url(js_url, timeout, session)
            if js_resp and js_resp.status_code == 200:
                found = _search_and_decode(js_resp.text[:100000], f"{js_url[:80]}", patterns)
                for f in found:
                    f["location"] = f"{js_url[:80]} | JS"
                all_found.extend(found)
                process_page(js_url, depth + 1)

        parsed = urlparse(base_url)
        for a in soup.find_all("a", href=True)[:30]:
            href = a["href"].strip()
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            next_url = urljoin(url, href)
            p = urlparse(next_url)
            if p.netloc == parsed.netloc and next_url not in seen_urls:
                process_page(next_url, depth + 1)

    process_page(base_url)
    return all_found
