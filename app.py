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
from scanners.crypto_scanner import WebSecAIScanner

# ═══════════════════════════════════════════════════════════════════════════════
# ФУНКЦИИ
# ═══════════════════════════════════════════════════════════════════════════════

def check_wallet(input_text):
    """Проверяет крипто-кошелек на scam риск"""
    wallet = re.search(r'[1-9A-HJ-NP-Za-km-z]{32,44}', input_text)
    if not wallet:
        return "❌ Кошелек не найден"
    
    addr = wallet.group()
    API_KEY = st.secrets.get("ETHERSCAN_API_KEY", "")
    
    if not API_KEY:
        return "❌ Добавьте ETHERSCAN_API_KEY в .streamlit/secrets.toml"
    
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&apikey={API_KEY}"
    try:
        resp = requests.get(url, timeout=5).json()
        if resp['status'] != '1':
            return "❌ Ошибка API"
        balance = int(resp['result'])
        risk = "🚨 **ВЫСОКИЙ РИСК МОШЕННИЧЕСТВА** (0 ETH)" if balance == 0 else f"✅ **БЕЗОПАСНО** | {balance/1e18:.4f} ETH"
        return f"**Адрес:** `{addr}`\n{risk}"
    except Exception:
        return "❌ Проверка не удалась"

def format_ai_recommendations(vulns):
    """Форматирует AI рекомендации для отображения"""
    if not vulns:
        return {
            'en': "🎉 Excellent! No critical vulnerabilities detected. Your web application appears secure against common attacks.",
            'ru': "🎉 Отлично! Критических уязвимостей не найдено. Ваше веб-приложение защищено от основных атак."
        }
    
    ai_en, ai_ru = ai_analysis(vulns)
    
    # Форматирование для красивого вывода
    en_formatted = f"""
**🔍 AI Security Analysis (English)**

**Detected vulnerabilities:** {', '.join(vulns)}

{ai_en}

**✅ Quick Fix Priority:**
1. {vulns[0]} - **CRITICAL** - Fix immediately
"""
    
    ru_formatted = f"""
**🔍 AI Анализ Безопасности (Русский)**

**Обнаруженные уязвимости:** {', '.join(vulns)}

{ai_ru}

**✅ Приоритет исправления:**
1. {vulns[0]} - **КРИТИЧЕСКАЯ** - Исправить немедленно
"""
    
    return {'en': en_formatted, 'ru': ru_formatted}

# ═══════════════════════════════════════════════════════════════════════════════
# НАСТРОЙКИ
# ═══════════════════════════════════════════════════════════════════════════════

st.set_page_config(page_title="WebSecAI Scanner", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%); }
.st-emojize { font-size: 1.2em; }
.ai-box { 
    background: rgba(15, 15, 35, 0.8); 
    border: 1px solid #667eea; 
    border-radius: 12px; 
    padding: 1.5rem; 
    margin: 1rem 0;
}
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# ЗАГОЛОВОК
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("# 🛡️ **WebSecAI** *AI Vulnerability Scanner*")
st.markdown("**Сканирование:** SQLi • XSS • CSRF • SSRF • Network • Crypto")
st.divider()

# ═══════════════════════════════════════════════════════════════════════════════
# ИНПУТЫ
# ═══════════════════════════════════════════════════════════════════════════════

col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input("🌐 URL для сканирования", "http://testphp.vulnweb.com/")
with col2:
    st.info("🔗 testphp.vulnweb.com = безопасный тестовый сайт")

run_scan = st.button("🚀 **СКАНИРОВАТЬ**", type="primary", use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# ОСНОВНОЕ СКАНИРОВАНИЕ
# ═══════════════════════════════════════════════════════════════════════════════

if run_scan and target_url.strip():
    if not target_url.startswith(('http://', 'https://')):
        st.error("❌ Добавьте http:// или https://")
    else:
        vulnerabilities = []
        
        # Progress & Status
        progress = st.progress(0)
        status = st.empty()
        
        scans = [
            ("SQL Injection", scan_sql_injection, 20),
            ("XSS", scan_xss, 40),
            ("CSRF", check_csrf_protection, 60),
            ("SSRF", scan_ssrf, 80),
        ]
        
        for name, scanner, percent in scans:
            status.text(f'🔍 {name}...')
            progress.progress(percent // 100)
            
            if scanner(target_url):
                vulnerabilities.append(name)
                st.warning(f"🕷️ **{name}** обнаружена!")
            else:
                st.success(f"✅ {name} чиста")
        
        # Network scan
        status.text('🌐 Network...')
        progress.progress(1.0)
        net_issues = scan_network_segmentation(target_url)
        if net_issues:
            for issue in net_issues:
                vulnerabilities.append(f"Network: {issue}")
                st.warning(f"🌐 {issue}")
        else:
            st.success("✅ Сеть сегментирована")
        
        progress.empty()
        status.empty()
        
        # ═══ CRYPTO ТЕСТ ═══
        st.markdown("---")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            test_result = check_wallet("t.me/fake/0x742d35cc6e3e8e1C5eD9a12345678901234567890123")
            st.markdown("### 🚨 Тестовый кошелек")
            st.markdown(test_result)
        with col_c2:
            st.info("💡 Пустые кошельки (0 ETH) = высокий риск мошенничества")
        
        # ═══ AI РЕКОМЕНДАЦИИ ═══
        st.markdown("---")
        st.markdown("## 🤖 **AI Рекомендации**")
        
        ai_recs = format_ai_recommendations(vulnerabilities)
        
        col_en, col_ru = st.columns(2)
        with col_en:
            with st.expander("🇺🇸 English Analysis", expanded=True):
                st.markdown(f"""
                <div class="ai-box">
                <h4>🔍 AI Security Report</h4>
                {ai_recs['en']}
                </div>
                """, unsafe_allow_html=True)
        
        with col_ru:
            with st.expander("🇷🇺 Анализ на русском", expanded=True):
                st.markdown(f"""
                <div class="ai-box">
                <h4>🔍 Отчет AI по безопасности</h4>
                {ai_recs['ru']}
                </div>
                """, unsafe_allow_html=True)
        
        # ═══ СТАТИСТИКА ═══
        col1, col2, col3 = st.columns(3)
        severity = "🟢 Низкий" if len(vulnerabilities) == 0 else "🟡 Средний" if len(vulnerabilities) < 3 else "🔴 Высокий"
        with col1: st.metric("Уязвимости", len(vulnerabilities))
        with col2: st.metric("Риск", severity)
        with col3: st.metric("Статус", "✅ Готово")

# ═══════════════════════════════════════════════════════════════════════════════
# ТАБЫ
# ═══════════════════════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4 = st.tabs(["📋 Результаты", "₿ Crypto", "🔍 Stego", "🧩 Расширения"])

with tab1:
    st.success("📊 Результаты сканирования выше!")

with tab2:
    st.subheader("₿ Проверка кошельков")
    wallet_input = st.text_input("📎 Telegram ссылка / адрес:")
    if st.button("🔍 Проверить", type="secondary"):
        result = check_wallet(wallet_input)
        st.markdown("### Результат:")
        st.markdown(result)

with tab3:
    st.warning("🔍 Стeganография в разработке")

with tab4:
    st.subheader("Chrome Extension Scanner")
    crx_file = st.file_uploader("📦 .crx файл", type="crx")
    if crx_file and st.button("🛡️ Сканировать"):
        with tempfile.NamedTemporaryFile(suffix=".crx", delete=False) as tmp:
            tmp.write(crx_file.read())
            tmp_path = tmp.name
        
        try:
            scanner = WebSecAIScanner()
            results = scanner.scan_crx(tmp_path)
            st.json(results)
            if results.get('critical', 0) > 0:
                st.error("🚨 Wallet Drainer!")
        finally:
            os.unlink(tmp_path)

st.markdown("---")
st.caption("🛡️ WebSecAI 2026 | Для пентестеров и разработчиков")
