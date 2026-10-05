import streamlit as st
from detector import investigate

st.set_page_config(page_title="SMS Sentinel", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main-title {font-size:3rem;font-weight:800;margin-bottom:0;}
.subtitle {color:#777;margin-bottom:25px;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ SMS SENTINEL</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Python-based suspicious SMS risk analyzer</div>',
    unsafe_allow_html=True
)

if "message" not in st.session_state:
    st.session_state.message = ""
if "result" not in st.session_state:
    st.session_state.result = None

st.markdown("### 🔎 Analyze an SMS")

message = st.text_area(
    "Paste the SMS you want to analyze:",
    value=st.session_state.message,
    height=200,
    placeholder="Paste a suspicious SMS here..."
)

c1, c2 = st.columns(2)

with c1:
    if st.button("🔎 ANALYZE SMS", use_container_width=True):
        if message.strip():
            st.session_state.message = message
            st.session_state.result = investigate(message)
        else:
            st.warning("Paste an SMS first.")


with c2:
    if st.button("🗑️ CLEAR", use_container_width=True):
        st.session_state.message = ""
        st.session_state.result = None
        st.rerun()

if st.session_state.result:
    r = st.session_state.result
    score = r["score"]

    if score >= 70:
        verdict, icon = "HIGH RISK", "🔴"
    elif score >= 40:
        verdict, icon = "SUSPICIOUS", "🟠"
    else:
        verdict, icon = "LOW RISK", "🟢"

    st.markdown("---")
    st.markdown("### 📋 Analysis Result")

    a, b = st.columns(2)
    with a:
        st.metric("Risk Score", f"{score}/100")
    with b:
        st.metric("Warning Signs", len(r["findings"]))

    st.markdown(f"## {icon} {verdict}")
    st.progress(score / 100)

    st.markdown("### 🚨 Warning signs detected")

    if r["findings"]:
        for finding in r["findings"]:
            st.markdown(
                f"**{finding['icon']} {finding['title']}**  \n"
                f"{finding['detail']}"
            )
    else:
        st.success("No major warning signs detected.")

    st.markdown("### 🧠 Analysis")
    st.write(r["summary"])

    st.markdown("### 🛡️ Recommendation")
    st.info(r["recommendation"])

    with st.expander("🔬 Technical Details"):
        st.write("Detected categories:", ", ".join(r["categories"]) or "None")
        st.write("Signals:", ", ".join(r["signals"]) or "None")
        st.write("URLs:", ", ".join(r["urls"]) or "None")

st.markdown("---")
st.caption("SMS Sentinel estimates message risk from observable signals. It does not prove that a message is fraudulent.")