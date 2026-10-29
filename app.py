import streamlit as st
import joblib
import os
import re
from src.components.data_transformation import AdversarialThreatTransformer
from src.components.heuristic_analyzer import extract_heuristics

# Page Configuration
st.set_page_config(
    page_title="ThreatShield | NextGen Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling & Glassmorphic Watermark
st.markdown("""
<style>
    /* Global Typography & Accent */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    code, pre {
        font-family: 'JetBrains Mono', monospace;
    }

    /* Top Hero Header */
    .hero-container {
        padding: 1.8rem 2rem;
        background: linear-gradient(135deg, rgba(17, 24, 39, 0.9) 0%, rgba(31, 41, 55, 0.7) 100%);
        border-radius: 14px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        margin-bottom: 2rem;
    }
    .hero-title {
        font-size: 2.1rem;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: #F9FAFB;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .hero-subtitle {
        color: #9CA3AF;
        font-size: 0.95rem;
        margin-top: 6px;
    }

    /* Metric Cards */
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }

    /* Transparent Watermark on Bottom-Right */
    .floating-watermark {
        position: fixed;
        bottom: 12px;
        right: 18px;
        z-index: 999999;
        font-family: 'Inter', sans-serif;
        font-size: 11px;
        font-weight: 500;
        letter-spacing: 0.4px;
        color: rgba(255, 255, 255, 0.32);
        background: rgba(0, 0, 0, 0.25);
        padding: 4px 10px;
        border-radius: 6px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        pointer-events: none;
        backdrop-filter: blur(4px);
    }
</style>

<div class="floating-watermark">
    Made By Adesh, Atharv, Rutuja and Tejaswini
</div>
""", unsafe_allow_html=True)

# Load Artifacts
@st.cache_resource
def load_models():
    model_path = os.path.join("outputs", "model.pkl")
    transformer_path = os.path.join("outputs", "transformer.pkl")
    model = joblib.load(model_path)
    transformer = joblib.load(transformer_path)
    return model, transformer

try:
    model, transformer = load_models()
except Exception as e:
    st.error(f"Error loading model artifacts: {e}")
    st.stop()

# Helper Functions
def extract_urls(text):
    return re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)

def check_urgency_words(text):
    keywords = ["urgent", "immediately", "verify", "suspend", "action required", "password", "bank", "wire", "invoice", "ssn"]
    found = [kw for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', text, re.I)]
    return found

# Sidebar Analytics & Meta
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("ThreatShield Hub")
    st.caption("AI-Powered Threat Detection Engine")
    
    st.markdown("---")
    st.subheader("Model Metadata")
    st.markdown("**Core Classifier:** Multinomial Naive Bayes")
    st.markdown("**Preprocessing:** Adversarial Normalizer")
    st.markdown("**Feature Extractor:** Heuristic Vectorizer")
    
    st.markdown("---")
    st.markdown("### Evaluation Presets")
    preset = st.selectbox(
        "Load sample test case:",
        ["None", "Phishing: Account Suspension", "Phishing: Fake Wire Transfer", "Legitimate: Meeting Schedule"]
    )

# Sample Presets Content
preset_texts = {
    "None": "",
    "Phishing: Account Suspension": "URGENT: Your bank account has been temporarily locked due to suspicious activity. Verify identity immediately at http://secure-login.bank-update.xyz to prevent permanent suspension.",
    "Phishing: Fake Wire Transfer": "Please review the attached invoice #84920 and wire transfer the payment of $4,250 to our updated vendor accounts by 5 PM today.",
    "Legitimate: Meeting Schedule": "Hi team, let's reschedule our quarterly project review meeting to Thursday at 3:00 PM in Conference Room B. Let me know if that works."
}

# Main Dashboard Hero
st.markdown("""
<div class="hero-container">
    <div class="hero-title">🛡️ NextGen Threat & Phishing Detection Engine</div>
    <div class="hero-subtitle">Engineered with Adversarial Normalization, Dual-Vector ML Classification, and Real-Time Heuristic Scanning.</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs(["🔍 Real-Time Message Inspection", "📁 Batch MBOX Analysis"])

# TAB 1: Real-Time Message Inspection
with tab1:
    default_input = preset_texts[preset] if preset != "None" else ""
    user_email = st.text_area(
        "Paste Raw Email Content or Headers Below:",
        value=default_input,
        height=180,
        placeholder="e.g. URGENT: Your corporate login credentials expire today. Click here to verify..."
    )

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        run_scan = st.button("⚡ Run Threat Analysis", type="primary", use_container_width=True)

    if run_scan:
        if not user_email.strip():
            st.warning("Please provide email text before running the inspection.")
        else:
            with st.spinner("Executing heuristics and inference pipeline..."):
                # Inference
                features = transformer.transform([user_email])
                prediction = model.predict(features)[0]
                probabilities = model.predict_proba(features)[0]
                threat_prob = probabilities[1] * 100

                # Threat Heuristics Extraction
                urls = extract_urls(user_email)
                urgency_words = check_urgency_words(user_email)

            st.markdown("---")
            st.subheader("Inspection Verdict & Analytics")

            # Score Cards
            m1, m2, m3 = st.columns(3)
            with m1:
                if prediction == 1:
                    st.error("🚨 THREAT / PHISHING DETECTED")
                else:
                    st.success("✅ LEGITIMATE / CLEAN")
            with m2:
                st.metric(label="Threat Probability", value=f"{threat_prob:.1f}%")
            with m3:
                st.metric(label="Confidence Level", value=f"{max(probabilities)*100:.1f}%")

            # Probability Progress Bar
            st.progress(float(threat_prob / 100))

            # Heuristics Breakdown
            st.markdown("#### Deep Heuristic Indicators")
            h_col1, h_col2 = st.columns(2)
            
            with h_col1:
                st.markdown("**Detected Links & URLs:**")
                if urls:
                    for u in urls:
                        st.markdown(f"- `{u}` ⚠️ *(External Hyperlink)*")
                else:
                    st.write("No external links found in the message body.")

            with h_col2:
                st.markdown("**Urgency & Phishing Triggers:**")
                if urgency_words:
                    st.write(", ".join([f"`{w}`" for w in urgency_words]))
                else:
                    st.write("No typical urgency manipulation words detected.")

# TAB 2: Batch Analysis Placeholder
with tab2:
    st.info("Upload an MBOX or batch raw export to process full mailbox archives concurrently.")
    uploaded_file = st.file_uploader("Upload .mbox file", type=["mbox"])
    if uploaded_file is not None:
        st.success(f"File uploaded: {uploaded_file.name}. Ready for batch parser integration.")