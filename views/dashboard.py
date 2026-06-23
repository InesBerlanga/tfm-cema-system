"""Dashboard view: overview operacional.

Estructura:
  - KPI strip (5 métricas)
  - Timeline CEMA dual-lane (todas las cadenas filtradas)
  - 2 columnas: top cadenas activas | eventos recientes
"""

from __future__ import annotations

import streamlit as st

from app_state import get_filters, get_pipeline
from ui_data import (
    build_events_df,
    build_ranking_df,
    get_filtered_chains,
    get_filtered_events,
)
from ui_plots import build_timeline_figure
from ui_theme import COLORS, inject_css, time_ago_str


def show() -> None:
    inject_css(st)
    st.title("Dashboard")
    st.caption("Cross-domain situational awareness")

    pipeline = get_pipeline()
    filters = get_filters()

    chains = get_filtered_chains(pipeline, **filters)
    events = get_filtered_events(
        pipeline,
        domains=filters["domains"],
        time_window=filters["time_window"],
    )
    cross_dom_chains = [c for c in chains if c.is_cross_domain]
    assets = {ev.asset_id for ev in events if ev.asset_id}

    # ============================================================  KPI strip
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Events", len(events))
    k2.metric("Active chains", len(chains))
    k3.metric(
        "Cross-domain",
        len(cross_dom_chains),
        delta=None if not cross_dom_chains else "alert",
        delta_color="inverse",  # makes it red
    )
    k4.metric("Assets touched", len(assets))
    k5.metric(
        "Last signal",
        time_ago_str(events[0].timestamp) if events else "—",
    )

    # ============================================================  Timeline
    st.markdown("#### Timeline")
    fig = build_timeline_figure(chains)
    st.plotly_chart(fig, use_container_width=True)

    # ============================================================  2-col layout
    col_chains, col_events = st.columns([1, 1])

    # ------- Top cadenas activas -------
    with col_chains:
        st.markdown("#### Active incidents")
        if not chains:
            st.caption("No incidents match the current filters.")
        else:
            top_chains = sorted(chains, key=lambda c: -c.total_strength)[:5]
            df = build_ranking_df(top_chains).drop(columns=["Tactics"])
            max_s = max(c.total_strength for c in top_chains)
            selection = st.dataframe(
                df,
                column_config={
                    "Strength": st.column_config.ProgressColumn(
                        "Strength",
                        min_value=0,
                        max_value=max(max_s, 1.0),
                        format="%.3f",
                    ),
                },
                selection_mode="single-row",
                on_select="rerun",
                hide_index=True,
                use_container_width=True,
                key="dashboard_chains_table",
            )
            if selection.selection.rows:
                idx = selection.selection.rows[0]
                if 0 <= idx < len(top_chains):
                    st.session_state["selected_chain_id"] = top_chains[idx].chain_id
                    st.switch_page("views/incidents.py")

    # ------- Eventos recientes -------
    with col_events:
        st.markdown("#### Recent events")
        if not events:
            st.caption("No events match the current filters.")
        else:
            recent = events[:10]  # ya ordenados DESC por get_filtered_events
            df = build_events_df(recent).drop(columns=["Date", "_event_id"])
            st.dataframe(
                df,
                column_config={
                    "Confidence": st.column_config.ProgressColumn(
                        "Confidence", min_value=0, max_value=1, format="%.2f"
                    ),
                },
                hide_index=True,
                use_container_width=True,
                key="dashboard_events_table",
            )


# Entry point cuando Streamlit ejecuta este script como página
show()
