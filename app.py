import streamlit as st
import requests
import re
import os
import tempfile
import time
import logging
from urllib.parse import urlparse
from ratelimit import limits, sleep_and_retry

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def is_valid_url(url):
    """Проверка валидности URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return False

def format_ai_recommendations(vulns):
    """Форматирование рекомендаций ИИ"""
    if not vulns:
        return {'en': '🎉 No vulnerabilities!', 'ru': '🎉 Уязвимостей нет!'}
    ai_en, ai_ru = ai_analysis(vulns)
    return {'en': ai_en, 'ru': ai_ru}

@sleep_and_retry
@limits(calls=10, period=60)  # Ограничение: 10 запросов в минуту
def perform_scan(url):
    """Выполнение полного сканирования"""
    vulnerabilities = []
    
    if scan_sql_injection(url):
        vulnerabilities.append("SQLi")
    if scan_xss(url):
        vulnerabilities.append("XSS")
    if check_csrf_protection(url):
        vulnerabilities.append("CSRF")
    if scan_ssrf(url):
        vulnerabilities.append("SSRF")
    
    net_issues = scan_network_segmentation(url)
    if net_issues:
        vulnerabilities.extend(net_issues)
    
    return vulnerabilities

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
    if not is_valid_url(target_url):
        st.error("❌ Invalid URL")
        st.stop()
        
    start_time = time.time()
    with st.spinner("Scanning..."):
        try:
            vulnerabilities = perform_scan(target_url)
            
            st.subheader("📊 Results")
            
            # Отображение результатов по каждому типу уязвимости
            st.write(f"✅ SQLi: {'Vulnerable' if 'SQLi' in vulnerabilities else 'Clean'}")
            st.write(f"✅ XSS: {'Vulnerable' if 'XSS' in vulnerabilities else 'Clean'}")
            st.write(f"✅ CSRF: {'Vulnerable' if 'CSRF' in vulnerabilities else 'Clean'}")
            st.write(f"✅ SSRF: {'Vulnerable' if 'SSRF' in vulneravilities else 'Clean'}")

            if vulnerabilities:
                st.error("Network issues found:")
                for issue in vulnerabilities:
                    if issue not in ["SQLi", "XSS", "CSRF", "SSRF"]:
                        st.write(f"- {issue}")
            else:
                st.success("✅ Network OK")

            # Крипто проверка
            st.markdown("---")
            st.subheader("₿ Crypto Test")
            crypto_result = check_wallet("0x742d35cc6e3e8e1C5eD9a12345678901234567890123")
            st.markdown(crypto_result)

            # AI анализ
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

            # Метрика найденных уязвимостей
            st.metric("Vulns found", len(vulnerabilities))

            # Время выполнения
            end_time = time.time()
            st.success(f"Scan completed in {end_time - start_time:.2f} seconds")

            # Экспорт результатов
            if st.button("Download Results"):
                results = {
                    "url": target_url,
                    "vulnerabilities": vulnerabilities,
                    "scan_time": end_time - start_time
                }
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                    import json
                    json.dump(results, f)
                    st.download_button(
                        label="Download JSON",
                        data=f.read(),
                        file_name="scan_results.json",
                        mime="application/json"
                    )

        except Exception as e:
            logging.error(f"Scan error: {e}")
            st.error(f"Error during scan: {str(e)}")

# Табы
tab1, tab2, tab3, tab4 = st.tabs(["📋 Results", "₿ Crypto", "🔍 Other", "🧩 Ext"])

with tab1:
    st.success("Results above!")

with tab2:
    wallet = st.text_input("Wallet check:")
    if st.button("Check"):
        if wallet:
            result = check_wallet(wallet)
            st.markdown(result)
        else:
            st.warning("Please enter a wallet address")

with tab3:
    st.info("More scanners coming...")

with tab4:
    crx = st.file_uploader("Upload .crx", type=["crx"])
    if crx:
        if st.button("Scan"):
            try:
                with tempfile.NamedTemporaryFile(suffix=".crx", delete=False) as tmp:
                    tmp.write(crx.read())
                    path = tmp.name
                    
                scanner = WebSecAIScanner()
                results = scanner.scan_crx(path)
                
                # Валидация результатов
                if isinstance(results, dict):
                    st.json(results)
                else:
                    st.error("Invalid scan results")
                    
                os.unlink(path)
                
            except Exception as e:
                logging.error(f"CRX scan error: {e}")
                st.error(f"Error scanning CRX: {str(e)}")

# Footer
st.markdown("""
---
🛡️ WebSecAI 2026
© All rights reserved
""")
