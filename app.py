import os

import streamlit as st

from analyzer import DEFAULT_MODEL, analyze

st.set_page_config(page_title="CyberShield AI", page_icon="🛡️")


def get_api_key() -> str:
    try:
        key = st.secrets.get("GROQ_API_KEY", "")
    except Exception:  # no secrets configured
        key = ""
    return key or os.getenv("GROQ_API_KEY", "")


def make_client(key: str):
    if not key:
        return None
    from groq import Groq
    return Groq(api_key=key)


st.title("🛡️ CyberShield AI")
st.caption("Paste a message or link. We analyse the text only - links are never opened.")

with st.sidebar:
    st.header("About")
    st.write("Checks messages and URLs for phishing and scams using "
             "smart rules plus AI (Groq).")
    key = get_api_key()
    if not key:
        st.warning("No API key found, so only rule-based checks will run.")
    model = DEFAULT_MODEL

text = st.text_area("Message or URL", height=180, max_chars=4000,
                    placeholder="e.g. Your account is suspended! Verify now: http://paypa1-secure.xyz/login")

if st.button("Check", type="primary"):
    if not text.strip():
        st.warning("Please paste a message or URL first.")
    else:
        with st.spinner("Analysing..."):
            result = analyze(text, make_client(key), model)

        msg = f"**{result.verdict.upper()}** (confidence {result.confidence}%)"
        if result.verdict == "harmful":
            st.error("🚨 " + msg)
        elif result.verdict == "suspicious":
            st.warning("⚠️ " + msg)
        else:
            st.success("✅ " + msg)

        st.write(f"**Advice:** {result.advice}")
        if result.category not in ("none", ""):
            st.write(f"**Category:** {result.category}")
        if result.reasons:
            st.write("**Why:**")
            for r in result.reasons:
                st.write(f"- {r}")
        if result.llm_error:
            st.info(f"AI check unavailable: {result.llm_error}")
        with st.expander("Technical details"):
            st.json({"urls_found": result.urls, "rule_score": result.rule_score,
                     "ai_verdict": result.llm_verdict})

st.divider()
st.caption("No tool is 100% accurate. When in doubt, don't click.")
