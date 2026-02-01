"""Футер с навигацией."""

def render() -> None:
    import streamlit as st
    st.markdown("---")
    st.markdown(
        "<div class='footer-bar'>"
        "© 2026 WebSecAI · "
        "<a href='https://github.com/credibility-index/WebSec-AI'>GitHub</a> · "
        "<a href='?tab=dash'>Обзор</a> · "
        "<a href='?tab=devsecops'>DevSecOps</a> · "
        "<a href='?tab=ctf_tracker'>Флаги CTF</a> · "
        "<a href='?tab=payloads'>Payloads</a> · "
        "<a href='?tab=stegano'>Стеганография</a> · "
        "<a href='?tab=kb'>База знаний</a> · "
        "<a href='?tab=export'>Экспорт</a> · "
        "<a href='?tab=osint'>OSINT</a> · "
        "<a href='?tab=ctf_hub'>CTF Hub</a> · "
        "<a href='?tab=ctf'>CTF Скан</a> · "
        "<a href='?tab=flags'>Поиск флагов</a> · "
        "<a href='?tab=recon'>Разведка</a> · "
        "<a href='?tab=exploit'>Эксплойт</a> · "
        "<a href='?tab=web'>Веб-безопасность</a> · "
        "<a href='?tab=ext'>Расширения</a> · "
        "<a href='?tab=fake'>Достоверность</a> · "
        "<a href='?tab=img'>AI-изображения</a> · "
        "<a href='?tab=crypto'>Крипто</a> · "
        "<a href='?tab=agent'>AI Агент</a>"
        "</div>",
        unsafe_allow_html=True
    )
