import time
from typing import List, Dict, Any, Optional

import requests
import streamlit as st

API_BASE_URL = "http://127.0.0.1:8000"


# =========================
# Backend helpers
# =========================

def get_policies_ui() -> List[str]:
    try:
        resp = requests.get(f"{API_BASE_URL}/policies", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Error fetching policies from backend: {e}")
        return []


def send_to_gateway(text: str, policy_name: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.post(
            f"{API_BASE_URL}/process_text",
            json={"text": text, "policy_name": policy_name},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Error calling backend: {e}")
        return None


def send_to_custom_gateway(text: str, keywords: List[str]) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.post(
            f"{API_BASE_URL}/process_text_custom",
            json={"text": text, "keywords": keywords},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Error calling backend (custom): {e}")
        return None


# =========================
# Streamlit UI
# =========================

st.set_page_config(page_title="LLM Safety Gateway", layout="wide")

if "messages" not in st.session_state:
    st.session_state.messages = []   # list of dicts: {role, text, result}


# Sidebar
with st.sidebar:
    st.markdown("### 🛡️ LLM Safety Gateway")
    st.caption("Structured firewall for LLM prompts and responses.")

    mode = st.radio(
        "Mode",
        ["Input Filter", "Response Filter", "Custom Keywords"],
        index=0,
    )

    policies = get_policies_ui()
    if not policies:
        policies = ["Enterprise_input"]

    policy_profile = st.selectbox("Policy profile", policies, index=policies.index("Enterprise_input") if "Enterprise_input" in policies else 0)

    if st.button("Clear chat"):
        st.session_state.messages = []

# Main layout
col_left, col_right = st.columns([1.3, 1.0])

# ---------------- LEFT: Chat Firewall ----------------
with col_left:
    st.markdown("## Chat Firewall")
    st.caption("Chat-style testing on the left, detailed policy analysis on the right.")

    user_prompt = st.text_area("User prompt", height=120, key="user_prompt")

    custom_keywords_input = ""
    if mode == "Custom Keywords":
        custom_keywords_input = st.text_input(
            "Custom keywords (comma separated)",
            value="",
            placeholder="bomb, hack bank, leak password",
        )

    send_btn = st.button("Send through gateway", type="primary")

    if send_btn and user_prompt.strip():
        start_ui = time.perf_counter()

        if mode == "Custom Keywords":
            keywords = [k.strip() for k in custom_keywords_input.split(",") if k.strip()]
            result = send_to_custom_gateway(user_prompt, keywords)
        elif mode == "Response Filter":
            # treat the text as LLM output -> run through Default_output
            result = send_to_gateway(user_prompt, "Default_output")
        else:  # Input Filter
            result = send_to_gateway(user_prompt, policy_profile)

        elapsed_ui = (time.perf_counter() - start_ui) * 1000.0

        if result:
            result["_ui_time_ms"] = elapsed_ui
            st.session_state.messages.insert(0, {
                "mode": mode,
                "text": user_prompt,
                "result": result,
            })

    st.markdown("### Conversation")

    if not st.session_state.messages:
        st.info("No messages yet. Try entering a prompt above.")
    else:
        for msg in st.session_state.messages:
            r = msg["result"]
            status = r["status"]
            text = msg["text"]

            if status == "BLOCK":
                badge = "🛑 BLOCKED"
            elif status in ("MASK", "REWRITE"):
                badge = "🟡 " + status
            else:
                badge = "🟢 PASS"

            with st.container():
                st.markdown(
                    f"<div style='padding:6px 10px;border-radius:6px;background:#2b2b2b;margin-bottom:4px;'>"
                    f"<strong>User:</strong> {text}</div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div style='padding:4px 10px;border-radius:6px;background:#1f1f1f;margin-bottom:16px;'>"
                    f"{badge} – {r.get('final_reason','')}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

# ---------------- RIGHT: Analysis ----------------
with col_right:
    st.markdown("## Analysis")

    if st.session_state.messages:
        latest = st.session_state.messages[0]["result"]

        gw_ms = latest.get("gateway_time_ms", 0.0)
        llm_ms = latest.get("llm_time_ms", 0.0)

        c1, c2 = st.columns(2)
        with c1:
            st.metric("Gateway time (ms)", f"{gw_ms:.2f}")
        with c2:
            st.metric("LLM time (ms)", f"{llm_ms:.2f}")

        st.markdown("---")
        st.markdown("### Policy chain")

        audit = latest.get("audit_log", [])
        if not audit:
            st.write("No audit log.")
        else:
            for entry in audit:
                pol = entry["policy"]
                st.markdown(
                    f"- **{pol}** — `{entry['status']}` – {entry['details']}"
                )

        st.markdown("---")

        st.markdown("### Original text")
        st.code(latest.get("original_text", ""), language="text")

        st.markdown("### Processed text")
        processed = latest.get("processed_text")
        if processed is None:
            st.code("BLOCKED – No processed text", language="text")
        else:
            st.code(processed, language="text")
    else:
        st.info("Send a prompt to see detailed analysis here.")
