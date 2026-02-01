import os
import json
import time
import logging
import requests
import concurrent.futures
from typing import List, Tuple, Dict, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("websec_ai")


def scan_sql_injection(url: str) -> bool:
    try:
        from scanners.sql_scanner import scan_sql_injection as _scan
        return _scan(url)
    except: return False

def scan_xss(url: str) -> bool:
    try:
        from scanners.xss import scan_xss as _scan
        return _scan(url)
    except: return False

def check_csrf_protection(url: str) -> bool:
    try:
        from scanners.csrf_scanner import check_csrf_protection as _scan
        return _scan(url)
    except: return False

def scan_ssrf(url: str) -> bool:
    try:
        from scanners.ssrf_scanner import scan_ssrf as _scan
        return _scan(url)
    except: return False

def scan_network_segmentation(url: str) -> List[str]:
    try:
        from scanners.network_scanner import scan_network_segmentation as _scan
        return _scan(url)
    except: return []


def ai_analysis(vulnerabilities: List[str]) -> Tuple[str, str]:
    """
    Анализ уязвимостей через OpenRouter.
    Основная: Arcee Trinity Large Preview (Free)
    Резерв: Meta Llama 3 8B (Free)
    """
    if not vulnerabilities:
        return ("✅ System Secure. No vulnerabilities found.", 
                "✅ Система безопасна. Уязвимостей не обнаружено.")

    vuln_list = ", ".join(vulnerabilities)
    api_key = os.environ.get("OPENROUTER_API_KEY")

    if not api_key:
        return (f"🚨 Vulns detected: {vuln_list} (AI Key Missing)", 
                f"🚨 Обнаружено: {vuln_list} (Нет ключа AI)")

    try:
        import requests
        headers = {
            "Authorization": f"Bearer {api_key}", 
            "Content-Type": "application/json",
            "HTTP-Referer": "https://websec-ai.streamlit.app",
            "X-Title": "WebSecAI"
        }
        
        def ask_ai(lang):
            sys_msg = "You are a cybersecurity expert. Short professional summary." if lang == "en" else "Ты эксперт по кибербезопасности. Краткое профессиональное резюме."
            user_msg = f"Analyze risks for: {vuln_list}" if lang == "en" else f"Анализ рисков для: {vuln_list}"
            
            models = [
                "arcee-ai/trinity-large-preview:free",
                "meta-llama/llama-3-8b-instruct:free"
            ]
            
            for model in models:
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": sys_msg},
                        {"role": "user", "content": user_msg}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 800
                }
                
                try:
                    r = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions", 
                        headers=headers, 
                        json=payload, 
                        timeout=45 
                    )
                    
                    if r.status_code == 200:
                        data = r.json()
                        if 'choices' in data and data['choices']:
                            return data['choices'][0]['message']['content']
                    
                    logger.warning(f"AI Model {model} failed: {r.status_code}")
                    continue 

                except requests.Timeout:
                    logger.warning(f"AI Model {model} timed out")
                    continue
                except Exception as e:
                    logger.error(f"AI Error: {e}")
                    continue
            
            return "AI Unavailable (All models failed)"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_en = executor.submit(ask_ai, "en")
            future_ru = executor.submit(ask_ai, "ru")
            return future_en.result(), future_ru.result()

    except Exception as e:
        logger.error(f"AI Global Error: {e}")
        return ("AI Unavailable", "ИИ недоступен")


def generate_report_content(results, lang="en"):
    timestamp = results["timestamp"]
    target = results["target"]
    vulns = results["vulnerabilities"]
    ai_text = results["ai_analysis"][lang]
    
    title = "WebSecAI Report" if lang == "en" else "Отчет WebSecAI"
    risk = "CRITICAL" if vulns else "CLEAN"
    
    md = f"# {title}\nTarget: {target}\nDate: {timestamp}\nStatus: {risk}\n\n## Vulnerabilities\n"
    if vulns:
        for v in vulns: md += f"- {v}\n"
    else:
        md += "No issues found.\n"
    
    md += f"\n## AI Analysis\n{ai_text}"
    return md


def full_scan(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    t0 = time.time()
    vulns = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_sql = executor.submit(scan_sql_injection, url)
        f_xss = executor.submit(scan_xss, url)
        f_csrf = executor.submit(check_csrf_protection, url)
        f_ssrf = executor.submit(scan_ssrf, url)
        f_net = executor.submit(scan_network_segmentation, url)
        
        if f_sql.result(): vulns.append("SQL Injection")
        if f_xss.result(): vulns.append("XSS")
        if f_csrf.result(): vulns.append("CSRF Missing")
        if f_ssrf.result(): vulns.append("SSRF")
        
        net_res = f_net.result()
        if net_res: vulns.extend(net_res)

    scan_time = round(time.time() - t0, 2)
    ai_en, ai_ru = ai_analysis(vulns)

    results = {
        "target": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": vulns,
        "metrics": {"scan_time": scan_time, "vuln_count": len(vulns), "score": max(0, 100 - len(vulns)*20)},
        "ai_analysis": {"en": ai_en, "ru": ai_ru}
    }
    
    results["reports"] = {
        "en_md": generate_report_content(results, "en"),
        "ru_md": generate_report_content(results, "ru")
    }
    
    return results

def scan_extension(file_obj) -> Dict[str, Any]:
    try:
        from scanners.extension_scanner import scan_crx_file
        return scan_crx_file(file_obj)
    except ImportError:
        logger.warning("Extension scanner module not found")
        return {'critical': 0, 'high': 0, 'threats': ["Module not installed"]}
    except Exception as e:
        logger.error(f"Extension scan error: {e}")
        return {'critical': 0, 'high': 0, 'threats': [f"Error: {e}"]}


def ctf_scan(url: str, profile: str = "ctf_quick", find_flags: bool = True, timeout: float = 30.0) -> Dict[str, Any]:
    """CTF-oriented scan using core.scanner (profiles, flag hunter)."""
    try:
        from core.scanner import run_scan
        return run_scan(url, profile_name=profile, timeout=timeout, find_flags=find_flags)
    except ImportError:
        return full_scan(url, timeout)


def deep_scan(url: str, max_subdomains: int = 15, max_pages_per_host: int = 8, max_urls_to_scan: int = 35, timeout: float = 90.0) -> Dict[str, Any]:
    """Глубокий скан: поддомены + краулинг + проверка всех URL."""
    try:
        from modules.deep_scan import deep_scan as _deep
        return _deep(url, max_subdomains=max_subdomains, max_pages_per_host=max_pages_per_host, max_urls_to_scan=max_urls_to_scan, timeout=timeout)
    except ImportError:
        return full_scan(url, timeout)


if __name__ == "__main__":
    import sys
    if len(sys.argv) <= 1 or sys.argv[1] in ("-h", "--help"):
        print("WebSecAI CTF / DevSecOps CLI")
        print("  ctf --url URL [--auto-exploit] [--find-flags] [--profile ...]")
        print("  recon --domain DOMAIN")
        print("  devsecops secrets|deps|sast|container|iac [--path PATH] [--dockerfile PATH]")
        print("  ctf flags list|add|export  |  ctf ctfd submit --url URL --token T --challenge-id ID --flag F")
        print("  ctf payloads sqli|xss|lfi|rce  |  ctf stegano IMAGE_PATH")
        print("  fuzz --url URL  |  flag-hunt --url URL [--max-pages 15]")
        print("  interactive  |  api")
        sys.exit(0 if len(sys.argv) <= 1 else 0)

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    def get_arg(name: str, short: str = None) -> str:
        opts = [f"--{name}"]
        if short:
            opts.append(f"-{short}")
        for i, a in enumerate(args):
            if a in opts and i + 1 < len(args):
                return args[i + 1]
        return None

    def has_flag(name: str) -> bool:
        return f"--{name}" in args

    if cmd == "recon":
        domain = get_arg("domain") or ""
        if not domain:
            print("Error: --domain required")
            sys.exit(1)
        try:
            from modules.recon import recon_domain
            r = recon_domain(domain, subdomain_limit=50)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)

    elif cmd == "fuzz":
        url = get_arg("url") or ""
        if not url:
            print("Error: --url required")
            sys.exit(1)
        try:
            from modules.automation import automation_run, chain_exploitation_hint
            r = automation_run(url, do_dir=True, do_param=True)
            r["chain_hint"] = chain_exploitation_hint([])
            print(json.dumps(r, indent=2, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)

    elif cmd == "flag-hunt":
        url = get_arg("url") or ""
        max_pages = int(get_arg("max-pages") or get_arg("max_pages") or "15")
        if not url:
            print("Error: --url required")
            sys.exit(1)
        try:
            from modules.flag_hunter import hunt_flags
            found = hunt_flags(url, max_pages=max_pages, check_robots_sitemap_git=True)
            print(json.dumps({"url": url, "count": len(found), "flags": found}, indent=2, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)

    elif cmd == "devsecops":
        sub = (args[0].lower() if args else "")
        path = get_arg("path") or "."
        if sub == "secrets":
            from modules.secrets_scan import scan_path as secrets_scan_path
            r = secrets_scan_path(path)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        elif sub == "deps":
            from modules.dependency_scan import dependency_scan as deps_scan
            r = deps_scan(path)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        elif sub == "sast":
            from modules.sast import sast_scan
            r = sast_scan(path)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        elif sub == "container":
            df = get_arg("dockerfile") or path
            from modules.container_scan import container_scan as container_scan_fn
            r = container_scan_fn(df)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        elif sub == "iac":
            from modules.iac_scan import iac_scan
            r = iac_scan(path)
            print(json.dumps(r, indent=2, ensure_ascii=False))
        else:
            print("Usage: devsecops secrets|deps|sast|container|iac [--path PATH] [--dockerfile PATH]")
            sys.exit(1)

    elif cmd == "ctf":
        sub = (args[0].lower() if args else "")
        if sub == "flags":
            act = args[1].lower() if len(args) > 1 else ""
            from modules.flag_tracker import list_flags, add, export_json, import_json, update_status, clear
            if act == "list":
                task_id = get_arg("task") or get_arg("task_id")
                status = get_arg("status")
                data = list_flags(task_id=task_id, status=status)
                print(json.dumps(data, indent=2, ensure_ascii=False))
            elif act == "add":
                t = get_arg("task") or get_arg("task_id") or "default"
                f = get_arg("flag")
                if not f:
                    print('Error: --flag required')
                    sys.exit(1)
                add(t, f, status=get_arg("status") or "pending", note=get_arg("note") or "")
                print(json.dumps({"added": t, "flag": f[:20] + "..."}))
            elif act == "export":
                print(export_json())
            elif act == "import":
                raw = sys.stdin.read() if not get_arg("file") else open(get_arg("file")).read()
                n = import_json(raw)
                print(json.dumps({"imported": n}))
            else:
                print("Usage: ctf flags list|add|export|import [--task ID] [--flag F] [--status ...]")
                sys.exit(1)
        elif sub == "ctfd":
            act = args[1].lower() if len(args) > 1 else ""
            if act == "submit":
                url = get_arg("url")
                token = get_arg("token")
                cid = get_arg("challenge-id") or get_arg("challenge_id")
                flag = get_arg("flag")
                if not all([url, token, cid, flag]):
                    print("Error: --url --token --challenge-id --flag required")
                    sys.exit(1)
                from modules.ctfd_client import ctfd_submit
                r = ctfd_submit(url, token, int(cid), flag)
                print(json.dumps(r, indent=2, ensure_ascii=False))
            else:
                print("Usage: ctf ctfd submit --url URL --token T --challenge-id ID --flag F")
                sys.exit(1)
        elif sub == "payloads":
            kind = args[1].lower() if len(args) > 1 else "sqli"
            from modules.payload_generator import get_sqli, get_xss, get_lfi, get_rce
            f = {"sqli": get_sqli, "xss": get_xss, "lfi": get_lfi, "rce": get_rce}.get(kind, get_sqli)
            for p in f():
                print(p)
        elif sub == "stegano":
            img = args[1] if len(args) > 1 else ""
            if not img:
                print("Usage: ctf stegano IMAGE_PATH")
                sys.exit(1)
            from modules.stegano import stegano_run
            r = stegano_run(img)
            def _str(o):
                return str(o)
            print(json.dumps(r, indent=2, ensure_ascii=False, default=_str))
        else:
            url = get_arg("url") or ""
            if url:
                profile = get_arg("profile") or "ctf_quick"
                find_flags = has_flag("find-flags") or not has_flag("no-flags")
                result = ctf_scan(url, profile=profile, find_flags=find_flags)
                if has_flag("auto-exploit") and result.get("vulnerabilities"):
                    try:
                        from core.exploiter import run_exploit
                        for v in result["vulnerabilities"]:
                            if isinstance(v, str) and v.upper() != "CSRF MISSING":
                                ex = run_exploit(v, url)
                                result.setdefault("exploits", []).append(ex)
                    except Exception as e:
                        result["exploit_error"] = str(e)
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print("Usage: ctf [--url URL] | ctf flags ... | ctf ctfd ... | ctf payloads ... | ctf stegano ...")
                sys.exit(1)

    elif cmd == "interactive":
        import subprocess
        subprocess.run(["streamlit", "run", "app.py"], cwd=os.path.dirname(os.path.abspath(__file__)))

    elif cmd == "api":
        try:
            import uvicorn
            uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=False)
        except Exception:
            import subprocess
            subprocess.run(["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"], cwd=os.path.dirname(os.path.abspath(__file__)))

    else:
        print("Unknown command. Use: ctf | recon | fuzz | flag-hunt | devsecops | interactive | api")
        sys.exit(1)
