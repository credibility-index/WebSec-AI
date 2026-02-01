import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

def exiftool(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": "exiftool", "raw": "", "parsed": {}}
    try:
        r = subprocess.run(
            ["exiftool", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0 and r.stdout:
            out["raw"] = r.stdout
            for line in r.stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    out["parsed"][k.strip()] = v.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(path)
            exif = img.getexif() or {}
            for tag_id, v in exif.items():
                name = TAGS.get(tag_id, tag_id)
                out["parsed"][str(name)] = str(v)
        except Exception:
            pass
    return out

def zsteg(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": "zsteg", "raw": "", "findings": []}
    try:
        r = subprocess.run(
            ["zsteg", path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.stdout:
            out["raw"] = r.stdout
            out["findings"] = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        out["error"] = "zsteg not installed (gem install zsteg)"
    return out

def steghide_info(path: str, passphrase: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": "steghide", "raw": "", "embedded": False}
    try:
        cmd = ["steghide", "info", path]
        if passphrase:
            cmd.extend(["--passphrase", passphrase])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, input="\n" if not passphrase else None)
        out["raw"] = (r.stdout or "") + (r.stderr or "")
        out["embedded"] = "embedded file" in out["raw"].lower() or "steghide" in out["raw"].lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        out["error"] = "steghide not installed"
    return out

def strings_file(path: str, min_len: int = 6) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": path, "strings": []}
    try:
        r = subprocess.run(
            ["strings", "-n", str(min_len), path],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if r.returncode == 0 and r.stdout:
            out["strings"] = r.stdout.splitlines()[:500]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        data = Path(path).read_bytes()
        import re
        out["strings"] = [m.decode("utf-8", errors="replace") for m in re.findall(rb"[\x20-\x7e]{6,}", data)][:500]
    return out

def stegano_run(image_path: str, passphrase: Optional[str] = None) -> Dict[str, Any]:
    return {
        "exiftool": exiftool(image_path),
        "zsteg": zsteg(image_path),
        "steghide": steghide_info(image_path, passphrase),
        "strings_sample": strings_file(image_path) if Path(image_path).exists() else {},
    }
