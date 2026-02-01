"""Unified scanner: runs existing scanners and optional async/parallel runs."""
import concurrent.futures
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.config import get_profile
from core.ai_engine import ai_analyze_vulnerabilities

CHECK_REPORT = {
    "sqli": (
        "SQL Injection",
        "Проверка GET/POST-параметров на инъекцию: Error-based, Boolean-based, Time-based (MySQL, PostgreSQL, Oracle, SQL Server, SQLite).",
    ),
    "xss": (
        "XSS (Cross-Site Scripting)",
        "Проверка отражённого и DOM XSS в параметрах q, search, input, data и др.; GET, POST, фрагмент URL.",
    ),
    "csrf": (
        "CSRF (защита форм)",
        "Проверка наличия CSRF-токенов в формах, meta, заголовках и cookies.",
    ),
    "ssrf": (
        "SSRF (Server-Side Request Forgery)",
        "Проверка параметров url, link, redirect, target на запрос к облачным метаданным (169.254.169.254), localhost, file://.",
    ),
    "network": (
        "Сеть и заголовки",
        "Открытые порты 8080/8443/8000/8888; утечка Server/X-Powered-By; отсутствие HSTS; режим DEBUG; обход 403 через X-Forwarded-For.",
    ),
    "cors": (
        "CORS",
        "Проверка отражения Origin, wildcard с credentials, доверие к null (OWASP).",
    ),
    "host_header": (
        "Host header",
        "Проверка отражения Host и X-Forwarded-Host; риск cache poisoning (OWASP).",
    ),
    "ssti": (
        "SSTI (Server-Side Template Injection)",
        "Проверка параметров на выполнение шаблонного кода (Jinja2, Twig, ERB).",
    ),
}


def _run_sqli(url: str) -> bool:
    try:
        from scanners.sql_scanner import scan_sql_injection
        return scan_sql_injection(url)
    except Exception:
        return False

def _run_xss(url: str) -> bool:
    try:
        from scanners.xss import scan_xss
        return scan_xss(url)
    except Exception:
        return False

def _run_csrf(url: str) -> bool:
    try:
        from scanners.csrf_scanner import check_csrf_protection
        return check_csrf_protection(url)
    except Exception:
        return False

def _run_ssrf(url: str) -> bool:
    try:
        from scanners.ssrf_scanner import scan_ssrf
        return scan_ssrf(url)
    except Exception:
        return False

def _run_network(url: str) -> List[str]:
    try:
        from scanners.network_scanner import scan_network_segmentation
        return scan_network_segmentation(url) or []
    except Exception:
        return []

def _run_cors(url: str) -> List[str]:
    try:
        from scanners.cors_scanner import scan_cors
        return scan_cors(url) or []
    except Exception:
        return []

def _run_host_header(url: str) -> List[str]:
    try:
        from scanners.host_header_scanner import scan_host_header
        return scan_host_header(url) or []
    except Exception:
        return []

def _run_ssti(url: str) -> List[str]:
    try:
        from scanners.ssti_scanner import scan_ssti
        return scan_ssti(url) or []
    except Exception:
        return []


def run_scan(
    url: str,
    profile_name: str = "ctf_quick",
    timeout: float = 30.0,
    find_flags: bool = False,
) -> Dict[str, Any]:
    """Run scan using named profile. Optionally run flag_hunter if find_flags."""
    profile = get_profile(profile_name)
    modules = profile.get("modules", ["sqli", "xss"])
    depth = profile.get("depth", 2)
    t0 = time.time()
    vulns: List[str] = []

    runner = {
        "sqli": _run_sqli,
        "xss": _run_xss,
        "csrf": _run_csrf,
        "ssrf": _run_ssrf,
        "cors": _run_cors,
        "host_header": _run_host_header,
        "ssti": _run_ssti,
    }

    checks: Dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {}
        for mod in modules:
            if mod in runner:
                futures[mod] = ex.submit(runner[mod], url)
        for mod, fut in futures.items():
            try:
                res = fut.result(timeout=timeout)
                if mod in ("network", "recon", "cors", "host_header", "ssti"):
                    if isinstance(res, list) and res:
                        vulns.extend(res)
                        checks[mod] = "vuln"
                    else:
                        checks[mod] = "clean"
                    continue
                if isinstance(res, list) and res:
                    vulns.extend(res)
                    checks[mod] = "vuln"
                elif res:
                    vulns.append(mod.upper())
                    checks[mod] = "vuln"
                else:
                    checks[mod] = "clean"
            except Exception:
                checks[mod] = "error"

        if "network" in modules:
            net = ex.submit(_run_network, url)
            try:
                net_res = net.result(timeout=timeout) or []
                vulns.extend(net_res)
                checks["network"] = "vuln" if net_res else "clean"
            except Exception:
                checks["network"] = "error"

    flags: List[Dict[str, Any]] = []
    if find_flags or profile.get("find_flags"):
        try:
            from modules.flag_hunter import hunt_flags
            flags = hunt_flags(url, max_pages=depth * 5)
        except Exception:
            pass

    scan_time = round(time.time() - t0, 2)
    ai_en, ai_ru = ai_analyze_vulnerabilities(vulns)

    report: List[Dict[str, Any]] = []
    for mod, (name, desc) in CHECK_REPORT.items():
        if mod not in checks:
            continue
        res = checks[mod]
        if res == "clean":
            result_text = "чисто"
        elif res == "vuln":
            result_text = "обнаружены признаки уязвимости"
        else:
            result_text = "ошибка проверки"
        report.append({
            "id": mod,
            "name": name,
            "description": desc,
            "result": res,
            "result_text": result_text,
        })

    return {
        "target": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "profile": profile_name,
        "vulnerabilities": vulns,
        "checks": checks,
        "report": report,
        "flags": flags,
        "metrics": {
            "scan_time": scan_time,
            "vuln_count": len(vulns),
            "score": max(0, 100 - len(vulns) * 20),
        },
        "ai_analysis": {"en": ai_en, "ru": ai_ru},
    }
