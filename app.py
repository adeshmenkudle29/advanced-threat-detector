import streamlit as st
import mailbox
import joblib
import pandas as pd
from src.components.data_transformation import AdversarialThreatTransformer
from src.components.heuristic_analyzer import ThreatHeuristicAnalyzer

st.set_page_config(page_title="AI Threat & Spam Intelligence", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_artifacts():
    transformer = joblib.load("outputs/transformer.pkl")
    model = joblib.load("outputs/model.pkl")
    heuristic = ThreatHeuristicAnalyzer()
    return transformer, model, heuristic

try:
    transformer, model, heuristic = load_artifacts()
except Exception as e:
    st.error(f"Error loading artifacts: {e}")
    st.stop()

st.title("🛡️ NextGen Threat & Spam Classification Engine")
st.caption("Engineered with Adversarial Normalization, Machine Learning, and Heuristic Phishing Scanners.")

tab1, tab2 = st.tabs(["Real-Time Inspection", "Batch MBOX Analysis"])

with tab1:
    st.subheader("Direct Message Inspection")
    email_text = st.text_area(
        "Paste Raw Email Body:", 
        height=180, 
        placeholder="e.g. URGENT: Verify your bank account at http://login-secure.xyz to avoid suspension..."
    )

    if st.button("Run Threat Analysis", type="primary"):
        if not email_text.strip():
            st.warning("Please provide email text to inspect.")
        else:
            # 1. ML Prediction
            features = transformer.transform([email_text])
            ml_pred = model.predict(features)[0]
            ml_prob = model.predict_proba(features)[0]

            # 2. Heuristic Analysis
            heuristics = heuristic.analyze(email_text)

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### Model Verdict")
                if ml_pred == 1 or heuristics["threat_score"] >= 50:
                    st.error(f"🚨 **HIGH RISK: SPAM / THREAT DETECTED**\n\nML Confidence: {ml_prob[1]*100:.1f}%")
                else:
                    st.success(f"✅ **SAFE: LEGITIMATE (HAM)**\n\nML Confidence: {ml_prob[0]*100:.1f}%")

            with col2:
                st.markdown("### Heuristic Threat Score")
                st.progress(heuristics["threat_score"] / 100)
                st.write(f"Risk Level: **{heuristics['threat_score']} / 100**")

            # 3. Transparent Explainability Panel
            st.divider()
            st.markdown("### 🔍 Threat Forensics & Explainability")
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                st.markdown("**Urgency & Social Engineering Triggers:**")
                if heuristics["urgency_triggers"]:
                    for kw in heuristics["urgency_triggers"]:
                        st.markdown(f"- ⚠️ Flagged Pattern: `{kw}`")
                else:
                    st.write("None detected.")

            with exp_col2:
                st.markdown("**URL & Domain Risk:**")
                if heuristics["detected_urls"]:
                    for u in heuristics["detected_urls"]:
                        flag = "🚨 High-Risk TLD" if u in heuristics["suspicious_urls"] else "ℹ️ Standard Link"
                        st.markdown(f"- {flag}: `{u}`")
                else:
                    st.write("No links present in text.")

with tab2:
    st.subheader("Bulk MBOX Archive Processing")
    uploaded_file = st.file_uploader("Upload .mbox archive", type=["mbox", "txt"])
    if uploaded_file:
        with open("temp.mbox", "wb") as f:
            f.write(uploaded_file.getbuffer())

        box = mailbox.mbox("temp.mbox")
        records = []
        for idx, msg in enumerate(box):
            payload = msg.get_payload()
            if isinstance(payload, list):
                payload = payload[0].get_payload()
            body = str(payload)
            
            feats = transformer.transform([body])
            pred = model.predict(feats)[0]
            h = heuristic.analyze(body)

            records.append({
                "Index": idx + 1,
                "Snippet": body.strip()[:80].replace("\n", " ") + "...",
                "Classification": "Spam / Threat" if (pred == 1 or h["threat_score"] >= 50) else "Ham (Clean)",
                "Risk Score": h["threat_score"]
            })

        if records:
            res_df = pd.DataFrame(records)
            st.dataframe(res_df, use_container_width=True)
            st.download_button(
                "Export Forensics Report (CSV)", 
                res_df.to_csv(index=False), 
                "threat_analysis_report.csv", 
                "text/csv"
            )