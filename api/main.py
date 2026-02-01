"""REST API for WebSecAI CTF / DevSecOps."""
import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

scans_store: Dict[str, Dict[str, Any]] = {}
flags_store: List[Dict[str, Any]] = []

app = FastAPI(title="WebSecAI API", version="1.0.0", description="CTF & DevSecOps scanning API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    url: str
    profile: Optional[str] = "ctf_quick"
    find_flags: Optional[bool] = True


class ExploitRequest(BaseModel):
    url: str
    vuln_type: str
    context: Optional[Dict[str, Any]] = None


class ReconRequest(BaseModel):
    domain: str
    subdomain_limit: Optional[int] = 50


class DevSecOpsPath(BaseModel):
    path: Optional[str] = "."


class CTFdSubmit(BaseModel):
    url: str
    token: str
    challenge_id: int
    flag: str


class FlagAdd(BaseModel):
    task_id: Optional[str] = "default"
    flag: str
    status: Optional[str] = "pending"


def _run_scan_task(scan_id: str, url: str, profile: str, find_flags: bool) -> None:
    try:
        from core.scanner import run_scan
        result = run_scan(url, profile_name=profile, find_flags=find_flags)
        result["scan_id"] = scan_id
        result["status"] = "completed"
        scans_store[scan_id] = result
        for f in result.get("flags", []):
            flags_store.append({**f, "scan_id": scan_id})
    except Exception as e:
        scans_store[scan_id] = {"scan_id": scan_id, "status": "failed", "error": str(e)}


@app.post("/api/scan")
async def api_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Start a scan; returns scan_id. Poll GET /api/scan/{id} for status."""
    scan_id = str(uuid.uuid4())
    scans_store[scan_id] = {"scan_id": scan_id, "status": "running", "target": req.url}
    background_tasks.add_task(_run_scan_task, scan_id, req.url, req.profile or "ctf_quick", req.find_flags or True)
    return {"scan_id": scan_id, "status": "running", "message": "Scan started. Poll /api/scan/{scan_id}"}


@app.get("/api/scan/{scan_id}")
async def api_scan_status(scan_id: str) -> Dict[str, Any]:
    """Get scan status and result."""
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_store[scan_id]


@app.get("/api/flags")
async def api_flags(scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List found flags; optional filter by scan_id."""
    if scan_id:
        return [f for f in flags_store if f.get("scan_id") == scan_id]
    return flags_store


@app.post("/api/exploit")
async def api_exploit(req: ExploitRequest) -> Dict[str, Any]:
    """Run exploitation for a given vuln type."""
    try:
        from core.exploiter import run_exploit
        return run_exploit(req.vuln_type, req.url, req.context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/recon")
async def api_recon(req: ReconRequest) -> Dict[str, Any]:
    """Run recon on domain (subdomains, tech, dorks)."""
    try:
        from modules.recon import recon_domain
        return recon_domain(req.domain, subdomain_limit=req.subdomain_limit or 50)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/report/{scan_id}")
async def api_report(scan_id: str) -> Dict[str, Any]:
    if scan_id not in scans_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans_store[scan_id]


@app.post("/api/devsecops/secrets")
async def api_devsecops_secrets(req: DevSecOpsPath) -> Dict[str, Any]:
    try:
        from modules.secrets_scan import scan_path
        return scan_path(req.path or ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/devsecops/deps")
async def api_devsecops_deps(req: DevSecOpsPath) -> Dict[str, Any]:
    try:
        from modules.dependency_scan import dependency_scan
        return dependency_scan(req.path or ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/devsecops/sast")
async def api_devsecops_sast(req: DevSecOpsPath) -> Dict[str, Any]:
    try:
        from modules.sast import sast_scan
        return sast_scan(req.path or ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/devsecops/iac")
async def api_devsecops_iac(req: DevSecOpsPath) -> Dict[str, Any]:
    try:
        from modules.iac_scan import iac_scan
        return iac_scan(req.path or ".")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ctf/flags")
async def api_ctf_flags_list(task_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    from modules.flag_tracker import list_flags
    return list_flags(task_id=task_id, status=status)


@app.post("/api/ctf/flags")
async def api_ctf_flags_add(body: FlagAdd) -> Dict[str, Any]:
    from modules.flag_tracker import add
    add(body.task_id or "default", body.flag, status=body.status or "pending")
    return {"added": True}


@app.post("/api/ctf/ctfd/submit")
async def api_ctfd_submit(req: CTFdSubmit) -> Dict[str, Any]:
    try:
        from modules.ctfd_client import ctfd_submit
        return ctfd_submit(req.url, req.token, req.challenge_id, req.flag)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ctf/payloads/{kind}")
async def api_ctf_payloads(kind: str) -> Dict[str, Any]:
    try:
        from modules.payload_generator import payloads_all
        all_p = payloads_all()
        if kind not in all_p:
            raise HTTPException(status_code=404, detail="Use sqli|xss|lfi|rce")
        return {"kind": kind, "payloads": all_p[kind]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FuzzRequest(BaseModel):
    url: str
    do_dir: Optional[bool] = True
    do_param: Optional[bool] = True


@app.post("/api/fuzz")
async def api_fuzz(req: FuzzRequest) -> Dict[str, Any]:
    """Run directory and parameter fuzzing."""
    try:
        from modules.automation import automation_run, chain_exploitation_hint
        result = automation_run(req.url, do_dir=req.do_dir is not False, do_param=req.do_param is not False)
        result["chain_hint"] = chain_exploitation_hint([])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class FlagHuntRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 15
    check_robots_git: Optional[bool] = True


@app.post("/api/flag-hunt")
async def api_flag_hunt(req: FlagHuntRequest) -> Dict[str, Any]:
    """Run Flag Hunter on URL (robots, sitemap, .git, .env, pages, JS, cookies, headers)."""
    try:
        from modules.flag_hunter import hunt_flags
        found = hunt_flags(
            req.url,
            max_pages=req.max_pages or 15,
            check_robots_sitemap_git=req.check_robots_git is not False,
        )
        for f in found:
            flags_store.append({**f, "scan_id": "flag-hunt"})
        return {"url": req.url, "count": len(found), "flags": found}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/learning/{vuln_type}")
async def api_learning(vuln_type: str) -> Dict[str, Any]:
    """Get step-by-step tutorial and practice lab for vulnerability type (sqli, xss, lfi, ssrf, rce)."""
    try:
        from core.ai_engine import ai_tutorial_for_vuln
        return ai_tutorial_for_vuln(vuln_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class Web3AnalyzeRequest(BaseModel):
    source: Optional[str] = None
    file_path: Optional[str] = None


@app.post("/api/web3/analyze")
async def api_web3_analyze(req: Web3AnalyzeRequest) -> Dict[str, Any]:
    """Analyze smart contract source or file (basic checks; use Mythril/Slither for full audit)."""
    try:
        from modules.web3_analyzer import analyze_contract_source, analyze_contract_file
        if req.source:
            return analyze_contract_source(req.source)
        if req.file_path:
            return analyze_contract_file(req.file_path)
        raise HTTPException(status_code=400, detail="Provide source or file_path")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root() -> Dict[str, str]:
    return {"service": "WebSecAI API", "docs": "/docs", "health": "/health"}


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}
