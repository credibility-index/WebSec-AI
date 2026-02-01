"""OSINT & Recon: subdomains, tech fingerprinting, dorks, DNS/WHOIS."""
import os
import re
import socket
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup


def _get_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "WebSecAI-Recon/1.0"
    return s


def subdomains_crtsh(domain: str, limit: int = 100) -> List[str]:
    """Subdomain enumeration via crt.sh (Certificate Transparency)."""
    results: set = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = _get_session().get(url, timeout=15)
        if r.status_code != 200:
            return list(results)
        data = r.json() if r.text else []
        for item in (data if isinstance(data, list) else [data])[:limit]:
            name = item.get("name_value") or item.get("common_name") or ""
            for part in name.replace(" ", "\n").split():
                part = part.strip().lower()
                if part.endswith("." + domain) or part == domain:
                    results.add(part)
    except Exception:
        pass
    return sorted(list(results))


def subdomains_dns(domain: str) -> List[str]:
    """Try common subdomain prefixes via DNS (A record)."""
    prefixes = ["www", "admin", "dev", "staging", "api", "mail", "ftp", "blog", "shop", "app", "cdn", "static", "beta", "test"]
    found = []
    for sub in prefixes:
        host = f"{sub}.{domain}"
        try:
            socket.gethostbyname(host)
            found.append(host)
        except (socket.gaierror, socket.timeout):
            pass
    return found


def tech_fingerprint(url: str) -> Dict[str, Any]:
    """Simple tech fingerprint from headers and meta tags (Wappalyzer-like)."""
    out: Dict[str, Any] = {"technologies": [], "server": None, "headers": {}}
    try:
        r = _get_session().get(url, timeout=10, allow_redirects=True)
        out["headers"] = dict(r.headers)
        out["server"] = r.headers.get("Server") or r.headers.get("X-Powered-By")
        if out["server"]:
            out["technologies"].append(out["server"])

        soup = BeautifulSoup(r.text[:100000], "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and gen.get("content"):
            out["technologies"].append(gen["content"])

        html = r.text.lower()
        if "wp-content" in html or "wordpress" in html:
            out["technologies"].append("WordPress")
        if "laravel" in html or "laravel_session" in str(r.cookies):
            out["technologies"].append("Laravel")
        if "django" in html or "csrftoken" in str(r.cookies):
            out["technologies"].append("Django")
        if "react" in html or "__next" in html:
            out["technologies"].append("React/Next.js")
        if "jquery" in html:
            out["technologies"].append("jQuery")
        if "bootstrap" in html:
            out["technologies"].append("Bootstrap")
    except Exception:
        pass
    return out


def google_dorks(domain: str, extra: Optional[List[str]] = None) -> List[str]:
    """Generate Google dork URLs for manual/search use."""
    base = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:config",
        f"site:{domain} ext:env",
        f"site:{domain} ext:sql",
        f"site:{domain} \"password\" OR \"api_key\"",
        f"site:github.com {domain}",
    ]
    if extra:
        base.extend(extra)
    return base


def github_dorks(domain: str, org: Optional[str] = None) -> List[str]:
    """GitHub/GitLab dorks for leaked credentials and repos."""
    base = [
        f"site:github.com {domain}",
        f'"{domain}" password OR api_key OR secret',
        f"github.com {domain} .env",
        f"github.com {domain} config.php",
        f"github.com {domain} DB_PASSWORD",
    ]
    if org:
        base.append(f"org:{org} {domain}")
    return base


def wayback_urls(domain: str, limit: int = 30) -> List[str]:
    """Fetch historical URLs from Wayback Machine (Archive.org)."""
    try:
        from modules.osint import wayback_urls as osint_wayback
        data = osint_wayback(domain, limit=limit)
        return data.get("urls", [])[:limit]
    except Exception:
        return []


def recon_domain(domain: str, subdomain_limit: int = 50, include_wayback: bool = True) -> Dict[str, Any]:
    """Full recon: subdomains (crt.sh + DNS), tech fingerprint, dorks, optional Wayback."""
    out: Dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "technologies": [],
        "dorks": [],
        "github_dorks": [],
        "wayback_urls": [],
    }
    subs_crt = subdomains_crtsh(domain, subdomain_limit)
    subs_dns = subdomains_dns(domain)
    out["subdomains"] = sorted(set(subs_crt + subs_dns))
    base_url = domain if "://" in domain else f"https://{domain}"
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    fp = tech_fingerprint(base_url)
    out["technologies"] = fp.get("technologies", [])
    out["dorks"] = google_dorks(domain)
    out["github_dorks"] = github_dorks(domain)
    if include_wayback:
        out["wayback_urls"] = wayback_urls(domain, limit=min(30, subdomain_limit))
    return out
