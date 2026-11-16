"""Scan page: paste or upload Python code and see the findings."""
import ui_common
import streamlit as st

from codeguard.pipeline import InputError, scan

ui_common.page_setup("Scan", "🔍")
EXAMPLES_DIR = ui_common.ROOT / "app" / "examples"

st.title("🔍 Scan Python code")
st.caption("Your code is analysed as text. It is never executed.")

st.session_state.setdefault("scan_source", "")
st.session_state.setdefault("scan_filename", "pasted_code.py")


def load_example() -> None:
    choice = st.session_state.example_choice
    if choice:
        st.session_state.scan_source = (EXAMPLES_DIR / choice).read_text(encoding="utf-8")
        st.session_state.scan_filename = choice


paste_tab, upload_tab = st.tabs(["Paste code", "Upload a file"])

with paste_tab:
    examples = sorted(p.name for p in EXAMPLES_DIR.glob("*.py"))
    st.selectbox("Load an example (optional)", [""] + examples, key="example_choice",
                 on_change=load_example, format_func=lambda n: n or "—")
    st.text_input("File name", key="scan_filename")
    st.text_area("Python source code", key="scan_source", height=320,
                 placeholder="user_input = input()\nresult = eval(user_input)")
    paste_clicked = st.button("Scan code", type="primary", key="scan_paste")

with upload_tab:
    uploaded = st.file_uploader("Python file (.py, up to 200 KB)", type=["py"])
    upload_clicked = st.button("Scan file", type="primary", key="scan_upload", disabled=uploaded is None)

source, filename = None, None
if paste_clicked:
    source, filename = st.session_state.scan_source, st.session_state.get("scan_filename") or "pasted_code.py"
elif upload_clicked and uploaded is not None:
    source, filename = uploaded.getvalue(), uploaded.name

if source is not None:
    try:
        with st.spinner("Running Bandit and the ML detector…"):
            result = scan(source, filename, store=ui_common.get_store())
        text = source.decode("utf-8-sig", errors="replace") if isinstance(source, bytes) else source
        st.session_state.current_result = result
        st.session_state.current_source = text
    except InputError as exc:
        st.session_state.pop("current_result", None)
        st.error(str(exc), icon="🚫")

if "current_result" in st.session_state:
    st.divider()
    ui_common.render_result(st.session_state.current_result, st.session_state.get("current_source"))

st.caption(ui_common.LIMITATIONS)
