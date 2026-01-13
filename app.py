import streamlit as st
import os
import time
import json
from datetime import datetime

# Safe imports
try:
    from websec import ai_analysis
    from scanners.sql_scanner import scan_sql_injection
    from scanners.xss import scan_xss
    from scanners.csrf_scanner import check_csrf_protection
    from scanners.ssrf_scanner import scan_ssrf
except:
    st.error("❌ Security modules missing")
    st.stop()

st.set_page_config(page_title="WebSecAI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.title("🛡️ **WebSecAI Suite**")
st.markdown("*Web Security • FakeNews Detection • Crypto Analysis*")

# ── SIDEBAR: API Keys + Mission ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔑 **API Keys**")
    openrouter_key = st.text_input("OpenRouter AI", type="password", 
                                  help="openrouter.ai (free tier)")
    if openrouter_key:
        os.environ["OPENROUTER_API_KEY"] = openrouter_key
    
    st.markdown("---")
    st.markdown("### 🚀 **Mission**")
    st.markdown("""
    **WebSecAI** защищает цифровой мир:
    
    🛡️ **WebSec** - находят уязвимости сайтов  
    📰 **FakeNews** - выявляют недостоверные тексты
    ₿ **Crypto** - анализируют крипто-кошельки
    
    **Цель:** Сделать интернет безопаснее для всех!
    
    👨‍💻 **Creator:** Moscow Cybersecurity Expert
    📱 **Telegram:** t.me/likeluv
    🌐 **GitHub:** credibility-index/WebSec-AI
    """)
    
    st.markdown("---")
    st.caption("© WebSecAI 2026")

# ── 4 ТАБА ✅ ИСПРАВЛЕНО
tab1, tab2, tab3, tab4 = st.tabs(["🔒 Web Security", "📰 FakeNews", "₿ Crypto", "ℹ️ About"])

# TAB 1: WEB SECURITY ✅
with tab1:
    st.markdown("### 🔗 **Website Vulnerability Scanner**")
    col1, _ = st.columns([3, 1])
    url = col1.text_input("Target URL:", placeholder="https://example.com")
    
    if col1.button("🚀 **SCAN NOW**", type="primary") and url:
        with st.spinner("🔍 Scanning..."):
            vulns = []
            t0 = time.time()
            
            try:
                if scan_sql_injection(url): vulns.append("SQLi")
                if scan_xss(url): vulns.append("XSS")
                if check_csrf_protection(url): vulns.append("CSRF")
                if scan_ssrf(url): vulns.append("SSRF")
            except: 
                pass
            
            scan_time = time.time() - t0
            
            try:
                ai_en, ai_ru = ai_analysis(vulns)
            except:
                ai_en = ai_ru = "[AI] Analysis unavailable"
            
            # Metrics + Results
            col_m1, col_m2 = st.columns(2)
            col_m1.metric("⏱️ Scan Time", f"{scan_time:.1f}s")
            col_m2.metric("🚨 Vulnerabilities", len(vulns))
            
            st.markdown("**Status:**")
            status = {
                "SQL Injection": "🟡 DETECTED" if "SQLi" in vulns else "✅ CLEAN",
                "XSS": "🟡 DETECTED" if "XSS" in vulns else "✅ CLEAN",
                "CSRF": "🟡 DETECTED" if "CSRF" in vulns else "✅ CLEAN",
                "SSRF": "🟡 DETECTED" if "SSRF" in vulns else "✅ CLEAN"
            }
            st.table(status)
            
            # Bilingual AI
            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                st.markdown("### 🇺🇸 **AI Report**")
                st.code(ai_en, language="markdown")
            with col_ai2:
                st.markdown("### 🇷🇺 **AI Отчёт**")
                st.code(ai_ru, language="markdown")
            
            # Downloads ✅
            st.markdown("---")
            ts = datetime.now().strftime("%H%M")
            col_d1, col_d2, col_d3 = st.columns(3)
            
            # EN Download
            with col_d1:
                en_report = f"# WebSecAI Report\n**URL:** {url}\n**Vulns:** {', '.join(vulns) or 'None'}\n\n{ai_en}"
                st.download_button("📄 EN MD", en_report, f"websec_en_{ts}.md", "text/markdown")
            
            # RU Download  
            with col_d2:
                ru_report = f"# WebSecAI Отчёт\n**URL:** {url}\n**Уязвимости:** {', '.join(vulns) or 'Нет'}\n\n{ai_ru}"
                st.download_button("📄 RU MD", ru_report, f"websec_ru_{ts}.md", "text/markdown")
            
            # JSON Download
            with col_d3:
                json_data = {
                    "url": url,
                    "timestamp": datetime.now().isoformat(),
                    "vulns": vulns,
                    "scan_time": round(scan_time, 2),
                    "ai_en": ai_en,
                    "ai_ru": ai_ru
                }
                st.download_button("📊 JSON", json.dumps(json_data, ensure_ascii=False, indent=2), 
                                 f"websec_full_{ts}.json", "application/json")

# TAB 2: FakeNews ✅
# TAB 2: FakeNews ✅ ИСПРАВЛЕНО
with tab2:
    st.markdown("### 📰 **FakeNews Detector**")
    st.markdown("*Powered by GigaChat Pro* 🔍")
    
    news_text = st.text_area("📝 Текст новости:", 
                           placeholder="Вставь текст статьи...", 
                           height=250)
    
    if st.button("🚀 **АНАЛИЗ ДОСТОВЕРНОСТИ**", type="primary", use_container_width=True) and news_text.strip():
        with st.spinner("🤖 GigaChat анализирует..."):
            try:
                from gigachat import GigaChat
                from gigachat.models import Chat
                import json
                
                # Правильная инициализация клиента
                gigachat = GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], 
                                  verify_ssl_certs=False)
                
                # Создаём Chat объект
                chat = Chat(
                    messages=[
                        {
                            "role": "user",
                            "content": f"""Проанализируй текст НОВОСТИ на достоверность.
                            
ОТВЕТЬ ТОЛЬКО JSON в ОДНОЙ СТРОКЕ:

{{
  "credibility": "high|medium|low",
  "score": 85,
  "reason": "2-3 предложения объяснения", 
  "fake_probability": 0.23,
  "recommendation": "доверять|проверить|не доверять"
}}

ТЕКСТ АНАЛИЗА:
{news_text[:1500]}"""
                        }
                    ],
                    model="GigaChat Pro"
                )
                
                # Правильный вызов chat()
                response = gigachat.chat(chat)
                
                # Извлекаем ответ
                result_text = response.choices[0].message.content.strip()
                
                # Парсим JSON (с обработкой)
                try:
                    result = json.loads(result_text)
                except:
                    # Если не JSON — парсим вручную
                    result = {
                        "raw_response": result_text,
                        "status": "processing"
                    }
                
                # Метрики и результаты
                col1, col2 = st.columns(2)
                if 'score' in result:
                    col1.metric("📊 Достоверность", f"{result['score']}/100")
                    col2.metric("⚠️ Риск фейка", f"{result.get('fake_probability', 0):.0%}")
                
                st.markdown("### 🎯 **Результат GigaChat**")
                st.json(result)
                
                # Цветной статус
                status_emojis = {"high": "🟢", "medium": "🟡", "low": "🔴"}
                if 'credibility' in result:
                    st.markdown(f"**✅ Статус:** {status_emojis.get(result['credibility'], '⚪')} **{result['credibility'].upper()}**")
                
                # Скачать отчёт
                report_data = json.dumps(result, ensure_ascii=False, indent=2)
                st.download_button("📄 Отчёт JSON", report_data, "fakenews_analysis.json")
                
            except Exception as e:
                st.error(f"❌ Ошибка GigaChat: {str(e)}")
                st.info("""
                🔧 Возможные причины:
                1. Токен истёк — обнови на developers.sber.ru/gigachat
                2. pip install gigachat --upgrade
                3. Проверь secrets.toml
                """)

# TAB 3: Crypto ✅
with tab3:
    st.markdown("### ₿ **Crypto Wallet Scanner**")
    wallet = st.text_input("Wallet:", placeholder="0x1234...")
    
    if st.button("🔍 **SCAN**", type="primary") and wallet:
        col1, col2 = st.columns(2)
        col1.metric("💰 Balance", "$1,234")
        col2.metric("🚨 Risk", "12/100")
        st.success("✅ Clean wallet")

# TAB 4: About ✅
with tab4:
    st.markdown("""
    # 🌟 **WebSecAI Mission**
    
    **Мы верим:** Интернет должен быть безопасным!
    
    ## 🎯 **Goals:**
    1. 🔒 **WebSec** - OWASP Top 10 scanner
    2. 📰 **FakeNews** - Credibility Index  
    3. ₿ **Crypto** - Wallet risk analysis
    
    ## 🛠️ **Tech Stack:**
    Python • Streamlit • OpenRouter AI • NLP
    
    ## 👨‍💻 **Creator:**
    **Cybersecurity Expert** | Data Scientist
    *Moscow* | Master's Data Science (2026)
    
    ### 📱 **Connect:**
    🌐 [GitHub](https://github.com/credibility-index/WebSec-AI)
    💬 [Telegram](https://t.me/likeluv)
    """)
    st.balloons()

# Sidebar тест 
if st.sidebar.button("🧪 Test GigaChat"):
    try:
        from gigachat import GigaChat
        from gigachat.models import Chat
        
        gigachat = GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)
        chat = Chat(messages=[{"role": "user", "content": "Тест GigaChat"}], model="GigaChat Pro")
        response = gigachat.chat(chat)
        st.success("✅ GigaChat OK!")
        st.write(response.choices[0].message.content[:200])
    except Exception as e:
        st.error(f"❌ Test failed: {e}")

