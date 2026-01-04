import streamlit as st
import requests
import re
import os
import tempfile

try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
    from scanners.network_scanner import scan_network_segmentation
    from scanners.crypto_scanner import WebSecAIScanner, check_wallet
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()

def format_ai_recommendations(vulns):
    if not vulns:
        return {'en': '🎉 No vulnerabilities!', 'ru': '🎉 Уязвимостей нет!'}
    ai_en, ai_ru = ai_analysis(vulns)
    return {'en': ai_en, 'ru': ai_ru}

st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp {background: linear-gradient(135deg,#0f0f23 0%,#1a1a2e 100%);}
.stButton>button {background:linear-gradient(45deg,#667eea,#764ba2);color:white;border-radius:25px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ WebSecAI Scanner")
st.markdown("**SQLi • XSS • CSRF • SSRF • Crypto**")
st.divider()

col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input("🌐 URL", "http://testphp.vulnweb.com/")
with col2:
    st.info("Test site")

if st.button("🚀 SCAN", type="primary"):
    if target_url.startswith(('http')):
        vulnerabilities = []
        st.subheader("📊 Results")
        
        with st.spinner("SQLi..."):
            if scan_sql_injection(target_url):
                vulnerabilities.append("SQLi")
                st.error("🕷️ SQLi!")
            else:
                st.success("✅ SQLi clean")
        
        with st.spinner("XSS..."):
            if scan_xss(target_url):
                vulnerabilities.append("XSS")
                st.error("🕷️ XSS!")
            else:
                st.success("✅ XSS clean")
        
        with st.spinner("CSRF..."):
            if check_csrf_protection(target_url):
                vulnerabilities.append("CSRF")
                st.error("🕷️ CSRF!")
            else:
                st.success("✅ CSRF OK")
        
        with st.spinner("SSRF..."):
            if scan_ssrf(target_url):
                vulnerabilities.append("SSRF")
                st.error("🕷️ SSRF!")
            else:
                st.success("✅ SSRF clean")
        
        with st.spinner("Network..."):
            net_issues = scan_network_segmentation(target_url)
            if net_issues:
                for issue in net_issues:
                    vulnerabilities.append(issue)
                    st.error(f"🌐 {issue}")
            else:
                st.success("✅ Network OK")
        
        st.markdown("---")
        st.subheader("₿ Crypto Test")
        crypto_result = check_wallet("0x742d35cc6e3e8e1C5eD9a12345678901234567890123")
        st.markdown(crypto_result)
        
        st.markdown("---")
        st.subheader("🤖 AI Analysis")
        ai_recs = format_ai_recommendations(vulnerabilities)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🇺🇸 EN**")
            st.write(ai_recs['en'])
        with col2:
            st.markdown("**🇷🇺 RU**")
            st.write(ai_recs['ru'])
        
        st.metric("Vulns found", len(vulnerabilities))
    else:
        st.error("❌ Invalid URL")

# Табы
tab1, tab2, tab3, tab4 = st.tabs(["📋 Results", "₿ Crypto", "🔍 Other", "🧩 Ext"])

with tab1:
    st.success("Results above!")

with tab2:
    wallet = st.text_input("Wallet check:")
    if st.button("Check"):
        st.markdown(check_wallet(wallet))

with tab3:
    st.info("More scanners coming...")

with tab4:
    crx = st.file_uploader("Upload .crx")
    if crx and st.button("Scan"):
        with tempfile.NamedTemporaryFile(suffix=".crx", delete=False) as tmp:
            tmp.write(crx.read())
            path = tmp.name
        scanner = WebSecAIScanner()
        results = scanner.scan_crx(path)
        st.json(results)
        os.unlink(path)

st.markdown("🛡️ WebSecAI 2026")
