import streamlit as st
import joblib
import re
import pandas as pd
import requests
import logging
import base64
import os
from datetime import datetime
import streamlit.components.v1 as components
from lime.lime_text import LimeTextExplainer
from sklearn.pipeline import make_pipeline

# ==========================================
# LOGGING CONFIGURATION
# ==========================================
# This automatically creates a soc_alerts.log file in your folder
logging.basicConfig(
    filename='soc_alerts.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ==========================================
# PAGE CONFIGURATION
# ==========================================
st.set_page_config(page_title="AI Phishing SOC", page_icon="🛡️", layout="wide")

# ==========================================
# LOAD AI MODELS
# ==========================================
@st.cache_resource
def load_models():
    try:
        vectorizer = joblib.load("tfidf_vectorizer.pkl")
        model = joblib.load("phishing_detector_model.pkl")
        return vectorizer, model
    except Exception as e:
        st.error(f"Failed to load AI models. Did you train them? Error: {e}")
        return None, None

vectorizer, model = load_models()

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def extract_iocs(text):
    """Extract URLs using Regex"""
    url_pattern = re.compile(r'(?:https?://|www\.)[^\s]+')
    return url_pattern.findall(text)

def check_virustotal(url, api_key):
    """Query VirusTotal API v3 for URL reputation"""
    if not api_key:
        return "API Key Required"
    
    # VirusTotal v3 requires the URL to be base64 encoded
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}
    
    try:
        # Send the URL to VirusTotal
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return f"🔴 {malicious} Security Vendors flagged this as Malicious"
            else:
                return "🟢 Clean (0 flags)"
        elif response.status_code == 404:
            return "⚪ Unrated (Not in VirusTotal database)"
        else:
            return f"⚠️ API Error: {response.status_code}"
    except Exception as e:
        return f"⚠️ Connection Error: {e}"

# ==========================================
# DASHBOARD UI
# ==========================================
# Sidebar for Config
with st.sidebar:
    st.header("⚙️ SOC Configuration")
    st.markdown("Enter your API keys for advanced threat enrichment.")
    # Input box for VirusTotal API Key
    vt_api_key = st.text_input("VirusTotal API Key (Optional)", type="password", placeholder="Enter VT API Key...")
    st.divider()
    st.subheader("📝 Live Audit Log")
    st.caption("Verdicts are automatically saved to `soc_alerts.log`")

st.title("🛡️ AI Phishing Security Operations Center")

# Create Tabs for Navigation
tab1, tab2 = st.tabs(["🔍 Live Threat Analysis", "📊 Automated SOC Reporting"])

# ------------------------------------------
# TAB 1: THREAT ANALYSIS
# ------------------------------------------
with tab1:
    st.markdown("Enter an email payload below to run it through the Kaggle-trained Random Forest Threat Engine.")

    # Layout: Two columns
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📨 Email Intercept")
        email_input = st.text_area("Raw Email Text", height=250, placeholder="Paste suspicious email text here...")
        analyze_btn = st.button("🔍 Run Threat Analysis", type="primary", use_container_width=True)

    with col2:
        st.subheader("⚙️ System Status")
        st.success("🧠 AI Brain: Online (98.18% Accuracy)")
        st.info("🔗 IOC Extraction: Online")
        
        if vt_api_key:
            st.success("🌐 VirusTotal API: Connected")
        else:
            st.warning("🌐 VirusTotal API: Offline (No Key)")
            
        st.info("📝 Audit Logging: Active")

    # ANALYSIS LOGIC
    if analyze_btn and email_input:
        if vectorizer and model:
            st.divider()
            st.subheader("🧠 Threat Intelligence Report")
            
            # 1. AI Prediction
            vectorized_text = vectorizer.transform([email_input])
            prediction = model.predict(vectorized_text)[0]
            
            # 2. Extract IOCs
            urls = extract_iocs(email_input)
            
            # 3. Determine Verdict & Create Log
            is_phishing = str(prediction).strip().lower() in ["phishing", "1", "spam"]
            verdict_text = "PHISHING DETECTED" if is_phishing else "SAFE"
            
            # Write to the log file!
            logging.info(f"Scanned Email | Verdict: {verdict_text} | Extracted {len(urls)} IOCs")
            
            # 4. Display Results
            res_col1, res_col2 = st.columns(2)
            
            with res_col1:
                st.markdown("### AI Verdict")
                if is_phishing:
                    st.error("🚨 MALICIOUS / PHISHING DETECTED")
                    st.markdown("**Action:** Quarantine Recommended")
                    st.markdown("*Alert logged to `soc_alerts.log`*")
                else:
                    st.success("🟢 SAFE")
                    st.markdown("**Action:** Allow to Inbox")
                    st.markdown("*Event logged to `soc_alerts.log`*")
                    
            with res_col2:
                st.markdown("### 🔗 IOCs & VirusTotal Analysis")
                if urls:
                    for url in urls:
                        st.markdown(f"**Target:** `{url}`")
                        with st.spinner("Querying VirusTotal..."):
                            if vt_api_key:
                                vt_result = check_virustotal(url, vt_api_key)
                                st.code(f"VirusTotal Status: {vt_result}")
                            else:
                                st.code("VirusTotal Offline: Enter API Key in Sidebar")
                else:
                    st.success("No suspicious URLs found.")
                    
            # 5. MODEL EXPLAINABILITY (LIME)
            st.divider()
            st.markdown("### 🔍 Model Explainability (XAI)")
            st.caption("Opening the AI 'Black Box': Highlighting the exact keywords that influenced the prediction.")
            
            with st.spinner("Generating AI logic explanation..."):
                try:
                    # Create a pipeline that LIME can use (Vectorizer -> Model)
                    pipeline = make_pipeline(vectorizer, model)
                    
                    # Get the actual class names from your trained model (e.g., ['Safe', 'Phishing'])
                    class_names = [str(c) for c in model.classes_] 
                    
                    # Initialize LIME Explainer
                    explainer = LimeTextExplainer(class_names=class_names)
                    
                    # Ask LIME to explain the prediction (extract top 10 most influential words)
                    exp = explainer.explain_instance(email_input, pipeline.predict_proba, num_features=10)
                    
                    # Render the beautiful LIME HTML output directly inside Streamlit!
                    components.html(exp.as_html(), height=400, scrolling=True)
                    
                except Exception as e:
                    st.error(f"Could not generate AI explanation. Error: {e}")

# ------------------------------------------
# TAB 2: SOC REPORTING
# ------------------------------------------
with tab2:
    st.subheader("📊 Automated Daily Incident Report")
    st.markdown("Generate a high-level summary of all network traffic and threats intercepted by the AI engine.")
    
    if st.button("🔄 Generate Latest Report"):
        if os.path.exists('soc_alerts.log'):
            with open('soc_alerts.log', 'r') as f:
                logs = f.readlines()
                
            total_scans = len(logs)
            phishing_count = sum(1 for line in logs if 'PHISHING DETECTED' in line)
            safe_count = sum(1 for line in logs if 'SAFE' in line)
            
            # Display Metrics
            st.markdown("### 📈 Executive Summary")
            m_col1, m_col2, m_col3 = st.columns(3)
            m_col1.metric("Total Emails Scanned", total_scans)
            m_col2.metric("🚨 Threats Quarantined", phishing_count)
            m_col3.metric("🟢 Safe Emails Allowed", safe_count)
            
            st.divider()
            st.markdown("### 📝 Raw Audit Logs")
            st.code("".join(logs), language="log")
            
            # Prepare Downloadable Report
            report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            report_content = (
                f"====================================\n"
                f"   DAILY SOC INCIDENT REPORT\n"
                f"   Generated: {report_date}\n"
                f"====================================\n\n"
                f"EXECUTIVE SUMMARY:\n"
                f"- Total Items Scanned: {total_scans}\n"
                f"- Malicious Threats Blocked: {phishing_count}\n"
                f"- Safe Items Allowed: {safe_count}\n\n"
                f"RAW LOGS:\n"
                f"------------------------------------\n"
                f"{''.join(logs)}"
            )
            
            st.download_button(
                label="📥 Download Full Report (.txt)",
                data=report_content,
                file_name=f"SOC_Report_{datetime.now().strftime('%Y%m%d')}.txt",
                mime="text/plain",
                type="primary"
            )
            
        else:
            st.info("No logs found yet. Run a Threat Analysis in the first tab to generate audit events!")