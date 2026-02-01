import os
import re
from typing import Dict, Any

import requests

def _etherscan_key() -> str:
    try:
        import streamlit as st
        return st.secrets.get("ETHERSCAN_API_KEY", "") or os.environ.get("ETHERSCAN_API_KEY", "")
    except Exception:
        return os.environ.get("ETHERSCAN_API_KEY", "")

BLACKLIST_PATTERNS = [
    r'^0x0+', r'^0x0000',
    r'[0]{10,}',
]

def validate_wallet(address: str) -> Dict[str, Any]:
    """Full wallet risk assessment"""
    if not re.match(r'^0x[a-fA-F0-9]{40}$|^(bc1[023456789acdefghjklmnpqrstuvwxyz]{39,59})$', address):
        return {"risk": "INVALID", "score": 100, "reason": "Wrong format"}
    
    result = {
        "address": address,
        "risk": "LOW",
        "score": 10,
        "balance_eth": 0,
        "tx_count": 0,
        "blacklisted": False,
        "reason": []
    }
    
    if _etherscan_key():
        try:
            api_key = _etherscan_key()
            balance_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
            tx_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={api_key}"
            
            bal_resp = requests.get(balance_url, timeout=5).json()
            tx_resp = requests.get(tx_url, timeout=5).json()
            
            if bal_resp['status'] == '1':
                result["balance_eth"] = int(bal_resp['result']) / 1e18
            if tx_resp['status'] == '1':
                result["tx_count"] = len(tx_resp['result'])
                
            if result["balance_eth"] == 0 and result["tx_count"] > 50:
                result["risk"] = "HIGH"
                result["score"] = 85
                result["reason"].append("Burner wallet: 0 ETH + high tx")
                
        except Exception as e:
            result["reason"].append(f"Etherscan API: {e}")
    
    for pattern in BLACKLIST_PATTERNS:
        if re.search(pattern, address):
            result["blacklisted"] = True
            result["risk"] = "CRITICAL"
            result["score"] = 100
            result["reason"].append("Blacklist pattern match")
            break
    
    if len(re.findall(r'[0]', address)) > 15:
        result["risk"] = max(result["risk"], "HIGH")
        result["score"] = max(result["score"], 70)
        result["reason"].append("Suspicious zero density")
    
    return result

def check_wallet(input_text: str) -> str:
    wallet_match = re.search(r'(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{39,59})', input_text)
    if not wallet_match:
        return "❌ No valid wallet (ETH/BTC) found"
    addr = wallet_match.group()
    if not _etherscan_key():
        return "⚠️ Add ETHERSCAN_API_KEY to .streamlit/secrets.toml or env (free tier OK)"
    result = validate_wallet(addr)
    try:
        import streamlit as st
        import json
        col1, col2, col3 = st.columns(3)
        col1.metric("🚨 Risk Score", f"{result['score']}/100")
        col2.metric("💰 Balance", f"{result['balance_eth']:.4f} ETH")
        col3.metric("📊 Tx Count", result['tx_count'])
        colors = {"LOW": "🟢", "HIGH": "🟡", "CRITICAL": "🔴", "INVALID": "⚪"}
        st.markdown(f"### {colors.get(result['risk'], '⚪')} **{result['risk']} RISK**")
        if result['reason']:
            st.warning("**Reasons:** " + " | ".join(result['reason']))
        st.download_button("📥 Full Report", json.dumps(result, indent=2), f"wallet_{addr[:8]}_{result['score']}.json")
    except Exception:
        pass
    return f"**{result['risk']}** | Score: {result['score']}"
