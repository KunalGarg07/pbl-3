"""Repository scan: upload a zipped Python project."""
import io
import zipfile

import ui_common
import pandas as pd
import streamlit as st

from codeguard.pipeline import InputError
from codeguard.repo.repo_scanner import MAX_ARCHIVE_BYTES, MAX_PY_FILES, scan_repository

ui_common.page_setup("Repository scan", "📦")
st.title("📦 Scan a project (.zip)")
st.caption(f"Upload a zipped Python project (up to {MAX_ARCHIVE_BYTES // 1_000_000} MB, {MAX_PY_FILES} .py files). "
           "Only .py files are extracted, into a temporary folder that is deleted after the scan. "
           "Archives with unsafe paths (for example ../) or symbolic links are rejected. Nothing is executed.")

uploaded = st.file_uploader("Project archive", type=["zip"])
if st.button("Scan project", type="primary", disabled=uploaded is None):
    data = uploaded.getvalue()
    try:
        with st.spinner("Extracting safely and scanning every Python file…"):
            result = scan_repository(data, uploaded.name, store=ui_common.get_store())
        # Keep the sources in this browser session only, for explanations and fixes.
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            sources = {}
            for name in result.files:
                try:
                    sources[name] = archive.read(name).decode("utf-8-sig")
                except (KeyError, UnicodeDecodeError):
                    pass
        st.session_state.repo_result, st.session_state.repo_sources = result, sources
    except InputError as exc:
        st.session_state.pop("repo_result", None)
        st.error(str(exc), icon="🚫")

result = st.session_state.get("repo_result")
if result is not None:
    st.divider()
    per_file = pd.DataFrame([{"File": f.file, "Severity": f.severity.value} for f in result.findings])
    if not per_file.empty:
        table = per_file.pivot_table(index="File", columns="Severity", aggfunc="size", fill_value=0)
        order = [s for s in ["Critical", "High", "Medium", "Low", "Informational"] if s in table.columns]
        table = table[order]
        table["Total"] = table.sum(axis=1)
        st.markdown("##### Findings per file")
        st.dataframe(table.sort_values(order[:2] + ["Total"], ascending=False), use_container_width=True)
        folders = per_file.assign(Folder=per_file["File"].str.rsplit("/", n=1).str[0])
        heat = folders.pivot_table(index="Folder", columns="Severity", aggfunc="size", fill_value=0)[order]
        st.markdown("##### Severity by folder")
        st.dataframe(heat.style.background_gradient(cmap="Reds", axis=None), use_container_width=True)
    st.caption(f"{len(result.files)} Python files scanned, {result.skipped_files} other files skipped.")
    ui_common.render_result(result, st.session_state.get("repo_sources"), key="repo")

st.caption(ui_common.LIMITATIONS)
