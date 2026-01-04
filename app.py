import streamlit as st
import requests
from websec import ai_analysis
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation
from scanners.crypto_scanner import check_wallet

# Базовые настройки страницы
st.set_page_config(
    page_title="WebSecAI Scanner",
    page_icon="🛡️",
    layout="centered",
)

# Немного стилей под лендинг
st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top, #111827, #020617);
        color: #e5e7eb;
    }
    .stButton>button {
        background: linear-gradient(to right, #38bdf8, #22c55e);
        color: #0b1120;
        border-radius: 999px;
        border: none;
        padding: 0.5rem 1.4rem;
        font-weight: 500;
        box-shadow: 0 10px 30px rgba(56, 189, 248, 0.5);
    }
    .stButton>button:hover {
        filter: brightness(1.05);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Заголовок и подзаголовок
st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ WebSecAI – AI Web Vulnerability Scanner</h1>"
    "<p style='color:#9ca3af;margin-top:4px'>Scan a URL for SQLi, XSS, CSRF, SSRF and basic network exposure, "
    "with AI-generated remediation tips (EN/RU).</p>",
    unsafe_allow_html=True,
)

st.markdown("---")

# Ввод URL
target_url = st.text_input("Target URL", "http://testphp.vulnweb.com/")

run_scan = st.button("Run scan")

if run_scan:
    if not target_url.strip():
        st.error("Please enter a valid URL.")
    else:
        vulnerabilities: list[str] = []

        st.subheader("Scan results")

        with st.spinner("Scanning for SQL Injection..."):
            if scan_sql_injection(target_url):
                vulnerabilities.append("SQL Injection")
                st.warning("SQL Injection: detected")
            else:
                st.success("SQL Injection: not detected")

        with st.spinner("Scanning for XSS..."):
            if scan_xss(target_url):
                vulnerabilities.append("XSS")
                st.warning("XSS: detected")
            else:
                st.success("XSS: not detected")

        with st.spinner("Scanning for CSRF..."):
            if check_csrf_protection(target_url):
                vulnerabilities.append("CSRF")
                st.warning("CSRF: protection missing on some forms")
            else:
                st.success("CSRF: no obvious issues")

        with st.spinner("Scanning for SSRF..."):
            if scan_ssrf(target_url):
                vulnerabilities.append("SSRF")
                st.warning("SSRF: potential issue detected")
            else:
                st.success("SSRF: not detected")

 with st.spinner("Scanning network segmentation..."):
            net_issues = scan_network_segmentation(target_url)
            if net_issues:
                st.warning("Network segmentation issues:")
                for issue in net_issues:
                    vulnerabilities.append(f"Network: {issue}")
                    st.write(f"- {issue}")
            else:
                st.success("Network segmentation: no obvious issues")

        # ✅ Crypto в цикле scan
        st.subheader("🚨 Crypto Scam Check")
        test_link = "t.me/fake/0x742d35cc6e3e8e1C5eD9a12345678901234567890123"  # Тест dead wallet
        crypto_risk = check_wallet(test_link)
        st.markdown(crypto_risk)

        st.subheader("AI Analysis")
        ai_en, ai_ru = ai_analysis(vulnerabilities)
API_KEY = st.secrets.get("ETHERSCAN_API_KEY", "")

def check_wallet(input_text):
    wallet = re.search(r'[1-9A-HJ-NP-Za-km-z]{32,44}', input_text)  # OK
    if not wallet:
        return "❌ No wallet found"
    addr = wallet.group()
    if not API_KEY:
        return "❌ Add ETHERSCAN_API_KEY to .streamlit/secrets.toml"
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&apikey={API_KEY}"
    resp = requests.get(url, timeout=5).json()  # ✅ requests.get
    if resp['status'] != '1':
        return "❌ API error"
    balance = int(resp['result'])
    risk = "🚨 HIGH SCAM (0 ETH)" if balance == 0 else f"✅ OK | {balance/1e18:.4f} ETH"
    return risk
    
        st.subheader("AI Analysis")
        ai_en, ai_ru = ai_analysis(vulnerabilities)
        st.markdown("**English:**")
        st.write(ai_en)
        st.markdown("**Русский:**")
        st.write(ai_ru)

        st.subheader("Summary")
        if vulnerabilities:
            st.write("Detected vulnerabilities:")
            for v in vulnerabilities:
                st.write(f"- {v}")
        else:
            st.write("No vulnerabilities detected by current checks.")
