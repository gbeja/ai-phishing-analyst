import base64
import json
import re
import time
from email import policy
from email.parser import Parser

from google import genai
from google.genai import types
import requests
import streamlit as st


def parse_email(raw_email_text):
    """Parses raw email text and extracts headers, body, and URLs (IOCs)."""
    msg = Parser(policy=policy.default).parsestr(raw_email_text)

    headers = {
        "Subject": msg.get("Subject", "No Subject"),
        "From": msg.get("From", "Not Found"),
        "Reply-To": msg.get("Reply-To", "Same as From (Not Specified)"),
        "Return-Path": msg.get("Return-Path", "Not Found"),
        "Authentication-Results": msg.get("Authentication-Results", "Not Found"),
    }

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    url_pattern = r'https?://[^\s<>"]+'
    urls = list(set(re.findall(url_pattern, body)))

    return {"headers": headers, "body": body.strip(), "urls": urls}


def check_url_virustotal(url, api_key):
    """Checks a single URL against VirusTotal's v3 API."""
    if not api_key:
        return {"url": url, "error": "Missing VirusTotal API Key"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": api_key}

    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    elif response.status_code == 404:
        return {
            "url": url,
            "status": "Unknown URL (Not yet scanned in VirusTotal database)",
        }
    else:
        return {"url": url, "error": f"API Error {response.status_code}"}


def analyze_with_gemini(parsed_data, vt_results, gemini_api_key):
    """Sends extracted email data and threat intel to Gemini for SOC triage."""
    client = genai.Client(api_key=gemini_api_key)

    system_prompt = """
    You are a Senior Tier 2 SOC Analyst. Analyze the provided email headers, email body, 
    and VirusTotal threat intelligence results. Write a clear, concise incident triage report with:
    1. **Verdict & Risk Score**: (e.g., Malicious / Suspicious / Benign — Low, Medium, High, or Critical)
    2. **Key Red Flags**: Bullet points explaining technical anomalies (SPF/DKIM/DMARC, Reply-To mismatch, VirusTotal detections) and social engineering tactics (urgency, impersonation).
    3. **Recommended Containment Actions**: 3 concrete steps the SOC team should take immediately.
    """

    evidence_payload = f"""
    === EXTRACTED HEADERS ===
    {json.dumps(parsed_data['headers'], indent=2)}

    === VIRUSTOTAL URL SCAN RESULTS ===
    {json.dumps(vt_results, indent=2)}

    === EMAIL BODY ===
    {parsed_data['body']}
    """
    models_to_try = ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-4-hydrogen"]

    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=evidence_payload,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.2,
                ),
            )
            return response.text, model_name
        except Exception as e:
            error_msg = str(e)
            if "503" in error_msg or "429" in error_msg or "404" in error_msg:
                time.sleep(2)
                continue
            raise e
    return (
           "All models are temporarily experiencing high demand. Please wait a few seconds and try again.",
           "None",
        )
st.set_page_config(
    page_title="AI SOC Phishing Analyst", page_icon="🛡️", layout="wide"
)

st.title("Automated Phishing Triage & Threat Intel Agent")
st.markdown(
    "Upload a `.eml` file or paste raw email headers & body to extract IOCs, enrich links via VirusTotal, and generate a Tier 2 SOC report."
)

with st.sidebar:
    st.header("API Configuration")
    vt_key = st.text_input("VirusTotal API Key", type="password")
    gemini_key = st.text_input("Google Gemini API Key", type="password")
    st.info(
        "Keys are used only for this session and are never saved to disk."
    )

uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])
default_sample = """From: "PayPal Security" <alert@paypa1-support-verify.com>
Reply-To: urgent-desk@evil-domain.ru
Subject: ACTION REQUIRED: Unusual sign-in detected
Authentication-Results: ://google.com; spf=fail; dkim=none; dmarc=fail

Dear Valued Customer,
We detected an unauthorized login attempt from a new device. Your account access has been temporarily limited.
Please verify your details within 24 hours to avoid permanent suspension:
http://wicar.org

Regards,
PayPal Account Protection"""

raw_text = st.text_area(
    "Or paste raw email content (headers + body):",
    value=default_sample,
    height=220,
)

if uploaded_file is not None:
    raw_text = uploaded_file.read().decode("utf-8", errors="ignore")

# Analyze Button
if st.button("Analyze Email", type="primary"):
    if not vt_key or not gemini_key:
        st.error(
            "Please enter both your VirusTotal and Gemini API keys in the left sidebar first."
        )
    elif not raw_text.strip():
        st.warning("Please upload an .eml file or paste email text to analyze.")
    else:
        with st.spinner("Extracting IOCs & querying VirusTotal..."):
            parsed = parse_email(raw_text)
            vt_findings = [
                check_url_virustotal(u, vt_key) for u in parsed["urls"]
            ]

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Extracted Security Headers")
            st.json(parsed["headers"])

        with col2:
            st.subheader("VirusTotal URL Enrichment")
            if vt_findings:
                st.json(vt_findings)
            else:
                st.info("No URLs found in the email body.")

        with st.spinner("AI SOC Analyst generating triage report..."):
            report, used_model = analyze_with_gemini(parsed, vt_findings, gemini_key)

        st.divider()
        st.subheader("Tier 2 SOC Analyst Report")
        st.caption(f"Analyzed using model: `{used_model}`")
        st.markdown(report)
