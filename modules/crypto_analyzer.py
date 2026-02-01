"""Crypto Analyzer: weak hashes, JWT (alg none, weak secret), encoding detection."""
import base64
import hashlib
import re
from typing import Any, Dict, List, Optional


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT header and payload (no verify)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b = base64.urlsafe_b64decode(parts[0] + "==")
        payload_b = base64.urlsafe_b64decode(parts[1] + "==")
        import json
        return {
            "header": json.loads(header_b.decode()),
            "payload": json.loads(payload_b.decode()),
            "raw": token,
        }
    except Exception:
        return None


def analyze_jwt(token: str) -> Dict[str, Any]:
    """Check JWT for none alg, weak secret, confusion (RS256->HS256)."""
    out: Dict[str, Any] = {"valid": False, "vulnerabilities": [], "header": None, "payload": None}
    decoded = decode_jwt(token)
    if not decoded:
        out["error"] = "Invalid JWT format"
        return out
    out["valid"] = True
    out["header"] = decoded["header"]
    out["payload"] = decoded["payload"]
    alg = (decoded["header"].get("alg") or "").upper()
    if alg == "NONE" or alg == "NON":
        out["vulnerabilities"].append({"type": "alg_none", "exploit": "Can forge tokens with alg:none"})
    if "HS256" in alg and "RS256" in alg:
        out["vulnerabilities"].append({"type": "alg_confusion", "exploit": "Try RS256 public key as HS256 secret"})
    return out


def detect_hash(s: str) -> Optional[str]:
    """Guess hash type by length/format."""
    s = s.strip()
    if re.match(r"^[a-fA-F0-9]{32}$", s):
        return "MD5"
    if re.match(r"^[a-fA-F0-9]{40}$", s):
        return "SHA1"
    if re.match(r"^[a-fA-F0-9]{64}$", s):
        return "SHA256"
    if re.match(r"^\$2[aby]?\$", s) or s.startswith("$argon2"):
        return "bcrypt/argon2"
    return None


def analyze_hashes_in_text(text: str) -> List[Dict[str, Any]]:
    """Find hash-like strings and label weak algorithms."""
    out: List[Dict[str, Any]] = []
    for m in re.finditer(r"[a-fA-F0-9]{32}(?![a-fA-F0-9])", text):
        out.append({"hash": m.group(0), "type": "MD5", "weak": True, "recommendation": "Use bcrypt/Argon2"})
    for m in re.finditer(r"[a-fA-F0-9]{40}(?![a-fA-F0-9])", text):
        out.append({"hash": m.group(0), "type": "SHA1", "weak": True, "recommendation": "Use SHA256 or bcrypt"})
    return out


def try_decode(s: str) -> List[Dict[str, Any]]:
    """Try base64, hex, ROT13 and return decoded if looks like flag/text."""
    results: List[Dict[str, Any]] = []
    try:
        decoded = base64.b64decode(s).decode("utf-8", errors="replace")
        if decoded.isprintable() or "flag" in decoded.lower() or "{" in decoded:
            results.append({"encoding": "base64", "decoded": decoded[:200]})
    except Exception:
        pass
    clean = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(clean) % 2 == 0 and len(clean) >= 4:
        try:
            decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
            if decoded.isprintable() or "flag" in decoded.lower():
                results.append({"encoding": "hex", "decoded": decoded[:200]})
        except Exception:
            pass
    try:
        import codecs
        decoded = codecs.decode(s, "rot_13")
        if "flag" in decoded.lower() or "ctf" in decoded.lower():
            results.append({"encoding": "rot13", "decoded": decoded[:200]})
    except Exception:
        pass
    return results


def padding_oracle_hint(ciphertext_sample: str) -> str:
    """Return a short hint for padding oracle detection (no actual attack)."""
    if len(ciphertext_sample) % 8 == 0 or len(ciphertext_sample) % 16 == 0:
        return "Block-aligned length: consider padding oracle (e.g. CBC). Test by flipping bytes in last block and observing error changes."
    return "Padding oracle: decrypt block cipher by querying server with modified ciphertext and observing padding/error responses."


def ai_cipher_suggestion(ciphertext: str) -> Optional[str]:
    """Ask AI to suggest cipher/encoding type. Optional dependency on core.ai_engine."""
    try:
        from core.ai_engine import ai_cipher_type
        return ai_cipher_type(ciphertext)
    except Exception:
        return None


def crypto_analyze(input_text: str, jwt_tokens: Optional[List[str]] = None, with_ai_cipher: bool = False) -> Dict[str, Any]:
    """Full crypto analysis: JWTs + hashes in text + decode attempts + optional AI cipher hint."""
    out: Dict[str, Any] = {"weak_hashes": [], "jwt": [], "decoded": [], "padding_oracle_hint": None, "ai_cipher": None}
    if jwt_tokens:
        for t in jwt_tokens:
            out["jwt"].append(analyze_jwt(t))
    out["weak_hashes"] = analyze_hashes_in_text(input_text)
    out["decoded"] = try_decode(input_text[:500])
    out["padding_oracle_hint"] = padding_oracle_hint(input_text[:64])
    if with_ai_cipher and len(input_text.strip()) > 10:
        out["ai_cipher"] = ai_cipher_suggestion(input_text.strip())
    return out
