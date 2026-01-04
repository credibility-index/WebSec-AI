import streamlit as st
import requests
import re
import os
import tempfile
from websec import ai_analysis
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation
from scanners.crypto_scanner import WebSecAIScanner, check_wallet

# ═══════════════════════════════════════════════════════════════════════════════
# 1. ФУНКЦИИ
# ═══════════════════════════════════════════════════════════════════════════════

def format_ai_recommendations(vulns):
    """Форматирует AI рекомендации"""
    if not vulns:
        return {
            'en': "🎉 No critical vulnerabilities detected!",
            'ru': "🎉 Критических уязвимостей не найдено!"
        }
    
    ai_en, ai_ru = ai_analysis(vulns)
    return {
        'en': f"**Found:** {', '.join(vulns)}\n\n{ai_en}",
        'ru': f"**Найдено:** {', '.join(vulns)}\n\n{ai_ru}"
    }

st.set_page_config(page_title="🛡️ WebSecAI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp {background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);}
.stButton>button {background: linear-gradient(45deg, #667eea, #764ba2); color:white; border-radius:25px;}
.ai-box {background:rgba(255,255,255,0.05); border:1px solid #667eea; border-radius:12px; padding:1.5rem;}
</style>
""", unsafe_allow_html=True)

st.markdown("# 🛡️ **WebSecAI Scanner**")
st.markdown("*SQLi • XSS • CSRF • SSRF • Network • Crypto*")
st.divider()

col1, col2 = st.columns([3,1])
with col1:
    target_url = st.text_input("🌐 Target URL", "http://testphp.vulnweb.com/")
with col2:
    st.info("💡 testphp.vulnweb.com = test site")

run_scan = st.button("🚀 **START SCAN**", type="primary", use_container_width=True)

if run_scan and target_url.strip():
    if not target_url.startswith(('http://','https://')):
        st.error("❌ Add http:// or https://")
    else:
        vulnerabilities = []
        st.subheader("📊 Scan Results")
        
        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # SQL Injection
        status_text.text('Scanning SQL Injection...')
        progress_bar.progress(0.2)
        if scan_sql_injection(target_url):
            vulnerabilities.append("SQL Injection")
            st.error("🕷️ SQL Injection DETECTED!")
        else:
            st.success("✅ SQL Injection: clean")
        
        # XSS
        status_text.text('Scanning XSS...')
        progress_bar.progress(0.4)
        if scan_xss(target_url):
            vulnerabilities.append("XSS")
            st.error("🕷️ XSS DETECTED!")
        else:
            st.success("✅ XSS: clean")
        
        # CSRF
        status_text.text('Scanning CSRF...')
        progress_bar.progress(0.6)
        if check_csrf_protection(target_url):
            vulnerabilities.append("CSRF")
            st.error("🕷️ CSRF protection MISSING!")
        else:
            st.success("✅ CSRF: protected")
        
        # SSRF
        status_text.text('Scanning SSRF...')
        progress_bar.progress(0.8)
        if scan_ssrf(target_url):
            vulnerabilities.append("SSRF")
            st.error("🕷️ SSRF DETECTED!")
        else:
            st.success("✅ SSRF: clean")
        
        # Network
        status_text.text('Scanning network...')
        progress_bar.progress(1.0)
        net_issues = scan_network_segmentation(target_url)
        if net_issues:
            st.error("🌐 Network issues:")
            for issue in net_issues:
                vulnerabilities.append(f"Network: {issue}")
                st.write(f"  • {issue}")
        else:
            st.success("✅ Network: secure")
        
        progress_bar.empty()
        status_text.empty()
        
        # Crypto Test
        st.markdown("---")
        st.subheader("₿ Crypto Check")
        test_wallet = check_wallet("t.me/fake/0x742d35cc6e3e8e1C5eD9a12345678901234567890123")
        st.markdown(test_wallet)
        
        # AI Analysis
        st.markdown("---")
        st.subheader("🤖 AI Recommendations")
        ai_recs = format_ai_recommendations(vulnerabilities)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🇺🇸 English**")
            st.markdown(f'<div class="ai-box">{ai_recs["en"]}</div>', unsafe_allow_html=True)
        with col2:
            st.markdown("**🇷🇺 Русский**")
            st.markdown(f'<div class="ai-box">{ai_recs["ru"]}</div>', unsafe_allow_html=True)
        
        # Metrics
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Vulnerabilities", len(vulnerabilities))
        with col2:
            st.metric("Risk Level", "HIGH" if len(vulnerabilities)>2 else "LOW")

tab1, tab2, tab3, tab4 = st.tabs(["📋 Results", "₿ Crypto", "🔍 Stego", "🧩 Extensions"])

with tab1:
    st.info("Results shown above!")

with tab2:
    st.subheader("Quick Wallet Check")
    wallet_input = st.text_input("Paste Telegram/wallet link:")
    if st.button("Check Wallet"):
        result = check_wallet(wallet_input)
        st.markdown(result)

with tab3:
    st.info("Steganography analysis coming soon")

with tab4:
    st.subheader("Chrome Extension Scanner")
    uploaded_file = st.file_uploader("Upload .crx", type="crx")
    if uploaded_file:
        with tempfile.NamedTemporaryFile(suffix=".crx", delete=False) as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name
        
        if st.button("Scan Extension"):
            try:
                scanner = WebSecAIScanner()
                results = scanner.scan_crx(tmp_path)
                st.json(results)
                if results.get('critical', 0) > 0:
                    st.error("🚨 CRITICAL issues found!")
            finally:
                os.unlink(tmp_path)

st.markdown("---")
st.caption("🛡️ WebSecAI 2026 | Cybersecurity Scanner")
