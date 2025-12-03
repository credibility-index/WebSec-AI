import os
import streamlit as st

from websec import ai_analysis
from scanners.sql_scanner import scan_sql_injection
from scanners.xss import scan_xss
from scanners.csrf_scanner import check_csrf_protection
from scanners.ssrf_scanner import scan_ssrf
from scanners.network_scanner import scan_network_segmentation


st.set_page_config(
    page_title="WebSecAI Scanner",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ WebSecAI – AI Web Vulnerability Scanner")
st.write(
    "Enter a URL to scan for common web vulnerabilities "
    "(SQLi, XSS, CSRF, SSRF) and basic network exposure hints."
)

target_url = st.text_input("Target URL", "http://testphp.vulnweb.com/")

run_scan = st.button("Run scan")

if run_scan:
    if not target_url.strip():
        st.error("Please enter a valid URL.")
    else:
        vulnerabilities = []

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
                for issue in net_issues:
                    vulnerabilities.append(f"Network: {issue}")
                st.warning("Network segmentation issues:")
                for issue in net_issues:
                    st.write(f"- {issue}")
            else:
                st.success("Network segmentation: no obvious issues")

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
