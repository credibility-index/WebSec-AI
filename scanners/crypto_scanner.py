import streamlit as st
import requests
import re
import os

API_KEY = st.secrets.get("ETHERSCAN_API_KEY", "")

def check_wallet(input_text):
    wallet = re.search(r'[1-9A-HJ-NP-Za-km-z]{32,44}', input_text)
    if not wallet:
        return "❌ No wallet found"
    addr = wallet.group()
    if not API_KEY:
        return "❌ Add ETHERSCAN_API_KEY to secrets.toml"
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&apikey={API_KEY}"
    resp = requests.get(url, timeout=5).json()
    if resp['status'] != '1':
        return "❌ API error"
    balance = int(resp['result'])
    risk = "🚨 HIGH SCAM (0 ETH)" if balance == 0 else f"✅ OK | {balance/1e18:.4f} ETH"
    return risk
