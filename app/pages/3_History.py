"""History page: previously completed scans."""
import ui_common
import pandas as pd
import streamlit as st

ui_common.page_setup("History", "🗂️")
st.title("🗂️ Scan history")

store = ui_common.get_store()
scans = store.list_scans(limit=200)

if not scans:
    st.info("No scans yet. Run one from the **Scan** page in the sidebar.")
    st.stop()

frame = pd.DataFrame(scans)
frame["created_at"] = pd.to_datetime(frame["created_at"]).dt.strftime("%Y-%m-%d %H:%M")
frame = frame.rename(columns={"scan_id": "Scan ID", "created_at": "Date (UTC)", "filename": "File",
                              "language": "Language", "total": "Findings", "high_or_worse": "High or worse"})

st.caption(f"{len(frame)} scan(s). Only a fingerprint (SHA-256) of the code is stored, not the code itself, "
           "unless CODEGUARD_STORE_SOURCE=true.")
event = st.dataframe(frame, hide_index=True, use_container_width=True, on_select="rerun",
                     selection_mode="single-row", key="history_table")

rows = event.selection.rows if event and event.selection else []
if rows:
    scan_id = frame.iloc[rows[0]]["Scan ID"]
    result = store.get(scan_id)
    if result:
        st.divider()
        ui_common.render_result(result, store.get_source(scan_id), key=f"hist_{scan_id}")
else:
    st.caption("Select a scan to open its report.")
