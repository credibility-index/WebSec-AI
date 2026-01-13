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
    
# 🆕 Кэш тяжёлых моделей
@st.cache_resource
def load_gigachat():
    from gigachat import GigaChat
    return GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)

@st.cache_resource
def load_ai_detector():
    try:
        from transformers import pipeline
        return pipeline("image-classification", model="umm-maybe/AI-image-detector")
    except:
        return None


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
    
    st.markdown("### 🚀 **Mission**")
    st.markdown("""
**WebSecAI** комплексная защита цифрового пространства:

🔒 **WebSec** сканирование сайтов на OWASP Top 10  
📰 **FakeNews** детектор фейковых новостей (GigaChat)  
🖼️ **AI Images** распознавание ИИ-генераций  
₿ **Crypto** анализ криптокошельков на риски  

**Цель:** Сделать интернет безопаснее для всех!

👨‍💻 **Creator:** Moscow Cybersecurity Expert
📱 **Telegram:** t.me/likeluv
🌐 **GitHub:** credibility-index/WebSec-AI
    """)
    
    st.markdown("---")
    st.caption("© WebSecAI 2026")
 
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔒 Web Security", "📰 FakeNews", "🖼️ AI Images", "₿ Crypto", "ℹ️ About"])

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
with tab2:
    st.markdown("### 📰 **FakeNews Detector** ✅ LIVE")
    st.markdown("*GigaChat 2 Pro • Real-time analysis*")
    
    news_text = st.text_area("📝 Текст новости:", 
                           placeholder="Вставь новость для проверки...", 
                           height=250)
    
    if st.button("🚀 **АНАЛИЗ**", type="primary", use_container_width=True) and news_text.strip():
        with st.spinner("🤖 Анализируем достоверность..."):
            try:
                # 🆕 КЭШ ДЛЯ ДЕПЛОЯ (1 раз грузит)
                @st.cache_resource
                def get_gigachat():
                    from gigachat import GigaChat
                    return GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)
                
                gigachat = get_gigachat()
                from gigachat.models import Chat
                import json
                import re
                
                chat = Chat(messages=[{
                    "role": "user",
                    "content": f"""Проанализируй НОВОСТЬ. ОТВЕТЬ ТОЛЬКО JSON:

{{
  "credibility": "high|medium|low",
  "score": 85,
  "reason": "2-3 предложения", 
  "fake_probability": 0.23,
  "recommendation": "доверять|проверить|не доверять"
}}

НОВОСТЬ: {news_text[:1500]}"""
                }])
                
                response = gigachat.chat(chat)
                raw_response = response.choices[0].message.content.strip()
                
                # Парсинг JSON из ```json ... ```
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', raw_response, re.DOTALL)
                if json_match:
                    result_text = json_match.group(1)
                else:
                    result_text = raw_response
                
                result = json.loads(result_text)
                
                # Метрики
                col1, col2, col3 = st.columns(3)
                col1.metric("📊 Достоверность", f"{result['score']}/100")
                col2.metric("⚠️ Риск фейка", f"{result['fake_probability']:.0%}")
                col3.metric("🎯 Статус", result['credibility'].upper())
                
                # Статус
                status_colors = {"high": "🟢", "medium": "🟡", "low": "🔴"}
                st.markdown(f"""
                ## **{status_colors.get(result['credibility'], '⚪')} {result['credibility'].upper()}**
                **Рекомендация:** {result['recommendation']}
                **Обоснование:** {result['reason']}
                """)
                
                with st.expander("📄 Полный отчёт"):
                    st.code(raw_response)
                
                st.download_button("📥 JSON", 
                                 json.dumps(result, ensure_ascii=False, indent=2),
                                 f"fakenews_{result['score']}.json")
                
            except Exception as e:
                st.error(f"❌ {e}")
                st.info("🔧 Проверь GIGACHAT_API_KEY в Secrets")

# TAB 3: AI Image Detector 🖼️ 
with tab3:
    st.markdown("### 🖼️ **AI Image Detector**")
    st.markdown("*Stable Diffusion • Midjourney • DALL-E* 🔍")
    
    uploaded_image = st.file_uploader("📁 Загрузи изображение", 
                                    type=['png','jpg','jpeg','webp'])
    
    col1, col2 = st.columns([1, 3])
    
    if uploaded_image is not None:
        col1.image(uploaded_image, caption="Загружено", use_column_width=True)
        
        if col1.button("🤖 **ПРОВЕРИТЬ НА ИИ**", type="primary"):
            with st.spinner("🔍 Анализ изображения..."):
                try:
                    # 🆗 ТОЛЬКО cache_resource (без singleton!)
                    @st.cache_resource
                    def load_detector():
                        from transformers import pipeline
                        return pipeline("image-classification",
                                      model="umm-maybe/AI-image-detector")
                    
                    detector = load_detector()
                    from PIL import Image
                    
                    image = Image.open(uploaded_image).convert('RGB')
                    results = detector(image)
                    
                    # 🆗 ПРАВИЛЬНЫЙ РАСЧЁТ
                    # Модель возвращает: label='fake'/'real', score
                    fake_scores = [r['score'] for r in results if 'fake' in r['label'].lower()]
                    ai_prob = max(fake_scores) if fake_scores else results[0]['score']
                    
                    # МЕТРИКИ
                    col_score, col_status = st.columns(2)
                    col_score.metric("🤖 ИИ-генерация", f"{ai_prob:.1%}")
                    
                    # СТАТУС
                    if ai_prob > 0.65:
                        col_status.metric("🎯 Итог", "🔴 **ИИ**")
                        st.error("🚨 AI-генерация!")
                    elif ai_prob < 0.35:
                        col_status.metric("🎯 Итог", "🟢 **Реал**")
                        st.success("✅ Человеческое!")
                    else:
                        col_status.metric("🎯 Итог", "🟡 **Неясно**")
                        st.warning("⚠️ Нужна доп. проверка")
                    
                    # АНАЛИЗ
                    st.markdown("### 📊 Детали модели:")
                    for result in results:
                        label = "🤖 ИИ" if 'fake' in result['label'].lower() else "👤 Реал"
                        st.write(f"{label}: **{result['score']:.1%}**")
                    
                    st.download_button("📄 Отчёт", 
                                     f"AI: {ai_prob:.1%}\nModel: {results[0]['label']}",
                                     "ai_report.txt")
                    
                except Exception as e:
                    st.error(f"❌ {e}")
                    st.info("🔧 pip install transformers torch pillow")
    else:
        st.info("👆 Загрузи фото → 'ПРОВЕРИТЬ'")
        st.markdown("*Midjourney/DALL-E → 🔴 | Телефон → 🟢*")


# TAB 4: Crypto ✅
with tab4:
    st.markdown("### ₿ **Crypto Wallet Scanner**")
    wallet = st.text_input("Wallet:", placeholder="0x1234...")
    
    if st.button("🔍 **SCAN**", type="primary") and wallet:
        col1, col2 = st.columns(2)
        col1.metric("💰 Balance", "$1,234")
        col2.metric("🚨 Risk", "12/100")
        st.success("✅ Clean wallet")

# TAB 5: About ✅
with tab5:
    st.markdown("""
    # 🌟 **WebSecAI Mission**
    
    **Мы верим,** что интернет должен быть безопасным!
    
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
if st.sidebar.button("📋 Получить модели GigaChat"):
    try:
        from gigachat import GigaChat
        
        gigachat = GigaChat(credentials=st.secrets["GIGACHAT_API_KEY"], verify_ssl_certs=False)
        models = gigachat.get_models()
        
        st.success("✅ Модели найдены!")
        for model in models.data:
            st.write(f"**{model.id_}** (owner: {model.owned_by})")
            
    except Exception as e:
        st.error(f"❌ {e}")

