"""CEMA Correlation System — Streamlit dashboard.

Multi-page app con tres vistas (Dashboard, Incidents, Events). Sidebar
global con filtros que persisten entre páginas, acciones de demo, y stats
del sistema.

Lanzar:  streamlit run app.py
"""

from __future__ import annotations

import streamlit as st

from app_state import get_pipeline
from ui_data import clear_database, reset_and_load_demo
from ui_theme import COLORS, inject_css


# ============================================================================
# Page config — DEBE ser la primera llamada a Streamlit
# ============================================================================

st.set_page_config(
    page_title="CEMA Correlation System",
    layout="wide",
    page_icon="📡",
    initial_sidebar_state="expanded",
)
inject_css(st)


# ============================================================================
# Sidebar — filtros globales + acciones + stats (compartido en todas las páginas)
# ============================================================================

pipeline = get_pipeline()

with st.sidebar:
    st.markdown(
        "<div style='font-size:1.05rem; font-weight:600; letter-spacing:0.01em; "
        "margin-bottom:0.4rem;'>CEMA Correlation</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<div style='color:{COLORS['text_muted']}; font-size:0.78rem; "
        "margin-bottom:1rem;'>Cyber-Electromagnetic threat detection</div>",
        unsafe_allow_html=True,
    )

    # ---------------- Filters ----------------
    st.markdown('<div class="sb-section">Filters</div>', unsafe_allow_html=True)

    st.multiselect(
        "Domains",
        options=["cyber", "ew"],
        default=["cyber", "ew"],
        key="flt_domains",
        help="Lenient: a chain is shown if it has at least one event in a "
             "selected domain. Cross-domain chains persist when filtering "
             "to a single domain.",
    )

    st.slider(
        "Min pair strength",
        min_value=0.0, max_value=1.0,
        value=0.2, step=0.05,
        key="flt_min_strength",
        help="Pairs with aggregate strength below this threshold are dropped "
             "before extracting chains. Raise to see only solid incidents.",
    )

    st.number_input(
        "Min events per chain",
        min_value=2, max_value=20,
        value=2,
        key="flt_min_events",
    )

    st.selectbox(
        "Time window",
        options=["1h", "6h", "24h", "all"],
        index=3,
        key="flt_time_window",
        help="Only consider events / chains within this time window.",
    )

    # ---------------- Actions ----------------
    st.markdown('<div class="sb-section">Actions</div>', unsafe_allow_html=True)

    if st.button("Load CEMA scenario", use_container_width=True, type="primary"):
        with st.spinner("Loading scenario…"):
            n = reset_and_load_demo(pipeline)
        st.success(f"Loaded {n} events.")
        st.session_state.pop("selected_chain_id", None)
        st.session_state["predictions"] = {}
        st.rerun()

    if st.button("Clear database", use_container_width=True):
        clear_database(pipeline)
        st.session_state.pop("selected_chain_id", None)
        st.session_state["predictions"] = {}
        st.rerun()

    # ---------------- Stats ----------------
    st.markdown('<div class="sb-section">System stats</div>',
                unsafe_allow_html=True)
    stats = pipeline.storage.stats()
    st.metric("Events", stats["events_total"])
    st.metric("Correlations", stats["correlations_total"])
    st.caption(
        f"cyber: {stats['events_cyber']} · ew: {stats['events_ew']}"
    )


# ============================================================================
# Navigation
# ============================================================================

pg_dashboard = st.Page(
    "views/dashboard.py", title="Dashboard", icon=":material/dashboard:",
    default=True,
)
pg_incidents = st.Page(
    "views/incidents.py", title="Incidents", icon=":material/warning:",
)
pg_events = st.Page(
    "views/events.py", title="Events", icon=":material/list:",
)

pg = st.navigation([pg_dashboard, pg_incidents, pg_events])
pg.run()