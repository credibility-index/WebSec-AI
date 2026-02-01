"""
Глубокий скан: поддомены + краулинг + проверка всех URL.
Проваливается в поддомены, обходит страницы каждого хоста, проверяет SQLi/XSS/CSRF/SSRF.
"""
import concurrent.futures
import time
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse


def _extract_domain(url: str) -> str:
    """Извлечь хост из URL."""
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        return host if host else ""
    except Exception:
        return ""


def _extract_base_domain(host: str) -> str:
    """Извлечь базовый домен для subdomain enum (vulnweb.com из testphp.vulnweb.com)."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def deep_scan(
    url: str,
    max_subdomains: int = 10,
    max_pages_per_host: int = 5,
    max_urls_to_scan: int = 25,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    """
    Глубокий скан: поддомены + краулинг + проверка всех найденных URL.

    1. Извлекает домен, получает поддомены (crt.sh + DNS)
    2. Краулит каждый хост (main + subdomains)
    3. Собирает URL, приоритет — с параметрами (?)
    4. Запускает full_scan на каждом URL
    5. Агрегирует результаты с привязкой к URL
    """
    from modules.recon import recon_domain
    from modules.crawler import crawl_urls
    import websec

    host = _extract_domain(url)
    if not host:
        return {
            "target": url,
            "error": "Не удалось извлечь домен",
            "vulnerabilities": [],
            "scanned_urls": [],
            "subdomains": [],
            "metrics": {"scan_time": 0, "vuln_count": 0, "score": 100},
            "ai_analysis": {"en": "", "ru": ""},
            "report": [],
        }

    scheme = urlparse(url).scheme or "https"
    base_domain = _extract_base_domain(host)
    t0 = time.time()

    # 1. Поддомены
    try:
        recon = recon_domain(base_domain, subdomain_limit=max_subdomains, include_wayback=False)
        subdomains = recon.get("subdomains", [])
    except Exception:
        subdomains = []

    if host and host not in subdomains:
        subdomains = [host] + [s for s in subdomains if s != host]
    subdomains = subdomains[: max_subdomains + 1]

    # 2. Базовые URL для краулинга
    base_urls = [f"{scheme}://{h}" for h in subdomains]

    # 3. Краулинг по каждому хосту
    all_urls: Set[str] = set()
    for base in base_urls:
        try:
            crawled = crawl_urls(base, max_pages=max_pages_per_host, timeout=8)
            for u in crawled:
                all_urls.add(u.rstrip("/"))
        except Exception:
            pass

    # Добавляем исходный URL, если его нет
    all_urls.add(url.rstrip("/"))

    # 4. Сортировка: сначала с параметрами
    def sort_key(u: str) -> Tuple[bool, str]:
        has_params = "?" in u
        return (not has_params, u)

    sorted_urls = sorted(all_urls, key=sort_key)[:max_urls_to_scan]

    # 5. Скан каждого URL (параллельно, 4 воркера)
    vulns: List[Dict[str, Any]] = []
    scanned: List[str] = []
    seen_vuln_keys: Set[str] = set()

    def _scan_one(u: str) -> List[Dict[str, str]]:
        try:
            res = websec.full_scan(u, timeout=5.0)
            return [{"url": u, "vuln": v} for v in res.get("vulnerabilities", [])]
        except Exception:
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(_scan_one, u): u for u in sorted_urls}
        for fut in concurrent.futures.as_completed(futures):
            u = futures[fut]
            try:
                items = fut.result()
                scanned.append(u)
                for item in items:
                    key = f"{item['url']}|{item['vuln']}"
                    if key not in seen_vuln_keys:
                        seen_vuln_keys.add(key)
                        vulns.append(item)
            except Exception:
                pass

    scan_time = round(time.time() - t0, 2)
    vuln_list = [f"{x['vuln']} @ {x['url']}" for x in vulns]
    vuln_count = len(vulns)
    score = max(0, 100 - vuln_count * 15)

    ai_en, ai_ru = websec.ai_analysis(vuln_list) if vuln_list else (
        "No vulnerabilities found.",
        "Уязвимостей не обнаружено.",
    )

    report = [
        {
            "id": "deep",
            "name": "Глубокий аудит (поддомены + краулинг)",
            "description": f"Проверено {len(subdomains)} хостов, {len(scanned)} URL.",
            "result": "vuln" if vulns else "clean",
            "result_text": "обнаружены уязвимости" if vulns else "чисто",
        }
    ]

    return {
        "target": url,
        "subdomains": subdomains,
        "scanned_urls": scanned,
        "vulnerabilities": vuln_list,
        "vuln_details": vulns,
        "timestamp": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile": "deep",
        "metrics": {
            "scan_time": scan_time,
            "vuln_count": vuln_count,
            "score": score,
            "hosts_checked": len(subdomains),
            "urls_scanned": len(scanned),
        },
        "ai_analysis": {"en": ai_en, "ru": ai_ru},
        "report": report,
        "checks": {"deep": "vuln" if vulns else "clean"},
        "reports": {
            "en_md": f"# WebSecAI Deep Scan\nTarget: {url}\nSubdomains: {len(subdomains)}\nURLs: {len(scanned)}\nVulns: {vuln_count}\n\n## AI\n{ai_en}",
            "ru_md": f"# WebSecAI Глубокий скан\nЦель: {url}\nПоддомены: {len(subdomains)}\nURL: {len(scanned)}\nУязвимости: {vuln_count}\n\n## AI\n{ai_ru}",
        },
    }
