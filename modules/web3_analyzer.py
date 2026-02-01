"""Web3/Blockchain CTF: базовый статический анализ контрактов. Полный аудит — Mythril/Slither."""
import re
from typing import Any, Dict, List, Optional


def analyze_contract_source(source: str) -> Dict[str, Any]:
    """
    Basic static checks on Solidity-like source (no compiler).
    Looks for reentrancy, unchecked external calls, sensitive storage.
    Full audit: use Mythril (myth analyze) or Slither (slither .).
    """
    out: Dict[str, Any] = {
        "vulnerabilities": [],
        "hints": [],
        "tools_recommended": ["Mythril", "Slither", "Echidna"],
    }
    if not source or len(source) < 50:
        return out

    text = source.replace("\r", "\n")
    lines = text.split("\n")

    if ".call" in text or ".transfer" in text or ".send" in text:
        out["hints"].append("External calls detected: check for reentrancy (state updates after .call/.transfer).")
        for i, line in enumerate(lines):
            if ".call" in line or ".transfer(" in line:
                out["vulnerabilities"].append({
                    "type": "Possible Reentrancy",
                    "line": i + 1,
                    "snippet": line.strip()[:80],
                    "recommendation": "Use Checks-Effects-Interactions or ReentrancyGuard.",
                })
                break

    if "call(" in text and "require(" not in text and "assert(" not in text:
        out["hints"].append("Low-level .call() without explicit return check: consider checking success.")

    if "delegatecall" in text:
        out["vulnerabilities"].append({
            "type": "Delegatecall",
            "snippet": "delegatecall detected",
            "recommendation": "Delegatecall runs in caller context; ensure trusted target.",
        })

    if "pragma solidity" in text and "0.8" not in text and ("+" in text or "*" in text):
        out["hints"].append("Pre-0.8 Solidity: consider SafeMath or upgrade to 0.8+ for built-in overflow checks.")

    if "owner" in text.lower() and "onlyOwner" not in text and "modifier" in text:
        out["hints"].append("Access control: check onlyOwner / role-based modifiers on sensitive functions.")

    return out


def analyze_contract_file(file_path: str) -> Dict[str, Any]:
    """Read file and run analyze_contract_source."""
    out: Dict[str, Any] = {"file": file_path, "vulnerabilities": [], "hints": [], "error": None}
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        result = analyze_contract_source(source)
        out["vulnerabilities"] = result["vulnerabilities"]
        out["hints"] = result["hints"]
        out["tools_recommended"] = result.get("tools_recommended", [])
    except FileNotFoundError:
        out["error"] = "File not found"
    except Exception as e:
        out["error"] = str(e)
    return out
