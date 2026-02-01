import base64
import binascii
import codecs
import os
import re
import subprocess
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_plus, quote_plus

def decode_misc(text: str, encoding: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"encoding": encoding, "success": False, "decoded": "", "error": None}
    try:
        if encoding in ("base64", "b64"):
            out["decoded"] = base64.b64decode(text).decode("utf-8", errors="replace")
            out["success"] = True
        elif encoding in ("base64url", "b64url"):
            out["decoded"] = base64.urlsafe_b64decode(text + "==").decode("utf-8", errors="replace")
            out["success"] = True
        elif encoding in ("hex", "hexadecimal"):
            clean = re.sub(r"[^0-9a-fA-F]", "", text)
            if len(clean) % 2 == 0:
                out["decoded"] = bytes.fromhex(clean).decode("utf-8", errors="replace")
                out["success"] = True
        elif encoding in ("rot13", "rot_13"):
            out["decoded"] = codecs.decode(text, "rot_13")
            out["success"] = True
        elif encoding in ("url", "url_decode"):
            out["decoded"] = unquote_plus(text)
            out["success"] = True
        elif encoding == "url_encode":
            out["decoded"] = quote_plus(text)
            out["success"] = True
        elif encoding in ("binary", "bin"):
            clean = re.sub(r"[^01]", "", text)
            if len(clean) % 8 == 0:
                out["decoded"] = "".join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
                out["success"] = True
        elif encoding == "reverse":
            out["decoded"] = text[::-1]
            out["success"] = True
    except Exception as e:
        out["error"] = str(e)
    return out

def forensics_file(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"exif": {}, "strings": [], "magic": "", "size": len(data)}
    try:
        result = subprocess.run(["file", "-b", "-"], input=data, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            out["magic"] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        if data[:4] == b"\x89PNG":
            out["magic"] = "PNG image"
        elif data[:2] == b"\xff\xd8":
            out["magic"] = "JPEG image"
        elif data[:6] in (b"GIF87a", b"GIF89a"):
            out["magic"] = "GIF image"
        elif data[:4] == b"%PDF":
            out["magic"] = "PDF document"
        elif data[:2] == b"MZ":
            out["magic"] = "PE/ELF executable (MZ)"
        else:
            out["magic"] = "unknown"
    try:
        from PIL import Image
        from io import BytesIO
        img = Image.open(BytesIO(data))
        exif = img.getexif() or {}
        for k, v in exif.items():
            try:
                out["exif"][str(k)] = str(v)
            except Exception:
                pass
    except Exception:
        pass
    try:
        import re as re_mod
        ascii_str = re_mod.findall(rb"[\x20-\x7e]{4,}", data)
        out["strings"] = [s.decode("ascii", errors="replace") for s in ascii_str[:200]]
    except Exception:
        pass
    return out

def reverse_info(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"magic": "", "strings": [], "entropy": 0.0}
    try:
        result = subprocess.run(
            ["file", "-b", "-"],
            input=data,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            out["magic"] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        if data[:2] == b"MZ":
            out["magic"] = "PE executable (Windows)"
        elif data[:4] == b"\x7fELF":
            out["magic"] = "ELF executable"
        else:
            out["magic"] = "binary"
    try:
        result = subprocess.run(["strings", "-n", "6", "-"], input=data, capture_output=True, timeout=10)
        if result.returncode == 0:
            out["strings"] = result.stdout.decode("utf-8", errors="replace").split("\n")[:150]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        ascii_str = re.findall(rb"[\x20-\x7e]{6,}", data)
        out["strings"] = [s.decode("ascii", errors="replace") for s in ascii_str[:150]]
    try:
        from collections import Counter
        import math
        c = Counter(data)
        n = len(data)
        out["entropy"] = round(-sum((v/n) * math.log2(v/n) for v in c.values() if v), 2)
    except Exception:
        pass
    return out

def suggested_tools(category: str) -> Dict[str, Any]:
    tools: Dict[str, Dict[str, Any]] = {
        "web": {
            "name": "Web",
            "description": "SQLi, XSS, SSRF, LFI, flag hunt, exploit.",
            "actions": ["CTF Scan", "Flag Hunter", "Exploit Playground", "Web Security Scanner"],
            "external": ["Burp Suite", "sqlmap", "XSStrike", "ffuf", "nikto"],
        },
        "reverse": {
            "name": "Reverse",
            "description": "Binary analysis, decompilation, strings, magic.",
            "actions": ["Upload file → magic/strings", "Reverse info"],
            "external": ["Ghidra", "IDA", "radare2", "Binary Ninja", "strings", "objdump"],
        },
        "misc": {
            "name": "Misc",
            "description": "Encoding/decoding, steganography hints.",
            "actions": ["Decode panel (base64/hex/ROT13/URL)", "Try decode"],
            "external": ["CyberChef", "dcode.fr", "stegsolve", "zsteg", "exiftool"],
        },
        "crypto": {
            "name": "Crypto",
            "description": "JWT, hashes, cipher identification.",
            "actions": ["JWT decode", "Hash detect", "Crypto analyzer", "AI decode hint"],
            "external": ["hashcat", "john", "jwt_tool", "RsaCtfTool", "ciphey"],
        },
        "pwn": {
            "name": "Pwn",
            "description": "Buffer overflow, ROP, shellcode.",
            "actions": ["Checksec-style (external)", "ROPgadget (external)"],
            "external": ["pwntools", "checksec", "ROPgadget", "one_gadget", "GDB", "gef"],
        },
        "forensics": {
            "name": "Forensics",
            "description": "EXIF, file carving, disk images, network captures.",
            "actions": ["Upload file → EXIF/strings", "Forensics file"],
            "external": ["exiftool", "binwalk", "foremost", "volatility", "Wireshark", "tshark"],
        },
    }
    return tools.get(category.lower(), {"name": category, "description": "", "actions": [], "external": []})

def pwn_binary_info(data: bytes) -> Dict[str, Any]:
    """Basic binary analysis for PWN: magic, strings, entropy, ELF/PE hints, optional checksec."""
    out: Dict[str, Any] = {"magic": "", "strings": [], "entropy": 0.0, "arch": "", "elf": {}, "checksec": None}
    rev = reverse_info(data)
    out["magic"] = rev["magic"]
    out["strings"] = rev["strings"][:80]
    out["entropy"] = rev["entropy"]

    if data[:4] == b"\x7fELF":
        try:
            ei_class = data[4]
            ei_data = data[5]
            e_machine = int.from_bytes(data[18:20], "little") if ei_data == 1 else int.from_bytes(data[18:20], "big")
            arch_map = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS"}
            out["arch"] = arch_map.get(e_machine, f"0x{e_machine:x}")
            out["elf"] = {"class": "32-bit" if ei_class == 1 else "64-bit", "machine": out["arch"]}
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
                f.write(data)
                tmp_path = f.name
            try:
                res = subprocess.run(
                    ["checksec", "--file=" + tmp_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout:
                    out["checksec"] = res.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                pass
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except Exception:
            pass
    elif data[:2] == b"MZ":
        out["arch"] = "PE (Windows)"
    return out


def all_categories() -> List[str]:
    return ["web", "reverse", "misc", "crypto", "pwn", "forensics"]
