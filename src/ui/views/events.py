"""Events view: log completo con filtros y detalle expandible por evento.

Filtros adicionales por encima de los globales del sidebar:
  - búsqueda por technique ID
  - búsqueda por asset
  - confianza mínima

Click en un evento (single-row selection) muestra debajo:
  - Detalle de cada técnica con el reasoning del LLM
  - Correlaciones donde participa este evento
  - JSON raw plegable
"""

from __future__ import annotations

import json
from uuid import UUID

import pandas as pd
import streamlit as st

from app_state import get_filters, get_pipeline
from schemas import ClassifiedEvent
from ui_data import build_events_df, get_filtered_events
from ui_theme import COLORS, code_chip, domain_pill, inject_css


def show() -> None:
    inject_css(st)
    st.title("Events")
    st.caption("Full event log. Use filters to narrow the search.")

    pipeline = get_pipeline()
    filters = get_filters()
    events = get_filtered_events(
        pipeline,
        domains=filters["domains"],
        time_window=filters["time_window"],
    )

    # ============================================================  Page filters
    with st.container(border=True):
        st.markdown("**Refine**")
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            tech_filter = st.text_input(
                "Technique contains",
                placeholder="e.g. T1190, TEW06",
                key="evt_tech_filter",
            ).strip().upper()
        with col2:
            asset_filter = st.text_input(
                "Asset contains",
                placeholder="e.g. GPS_, NAV-",
                key="evt_asset_filter",
            ).strip()
        with col3:
            min_conf = st.slider(
                "Min confidence",
                min_value=0.0, max_value=1.0,
                value=0.0, step=0.05,
                key="evt_min_conf",
            )

    # Apply page filters
    filtered_events = []
    for ev in events:
        if min_conf > 0.0:
            max_c = max((t.confidence for t in ev.techniques), default=0.0)
            if max_c < min_conf:
                continue
        if tech_filter:
            tech_str = " ".join(t.technique_id.upper() for t in ev.techniques)
            if tech_filter not in tech_str:
                continue
        if asset_filter:
            if not ev.asset_id or asset_filter.lower() not in ev.asset_id.lower():
                continue
        filtered_events.append(ev)

    st.caption(f"{len(filtered_events)} event(s)")

    if not filtered_events:
        st.info("No events match the current filters.")
        return

    # ============================================================  Events table
    df = build_events_df(filtered_events)
    selection = st.dataframe(
        df.drop(columns=["_event_id"]),
        column_config={
            "Confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0, max_value=1, format="%.2f"
            ),
        },
        hide_index=True,
        use_container_width=True,
        selection_mode="single-row",
        on_select="rerun",
        key="events_table",
    )

    # ============================================================  Detail panel
    if selection.selection.rows:
        idx = selection.selection.rows[0]
        if 0 <= idx < len(filtered_events):
            ev = filtered_events[idx]
            _render_event_detail(ev, pipeline)


def _render_event_detail(ev: ClassifiedEvent, pipeline) -> None:
    """Panel de detalle: técnicas con reasoning, correlaciones, JSON raw."""
    st.markdown('<div class="section-divider">Event detail</div>',
                unsafe_allow_html=True)

    # Header
    pill = domain_pill(ev.domain)
    st.markdown(
        f"{pill}<code>{ev.event_id}</code>  ·  "
        f"<b>{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</b>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"<span style='color:#94a3b8;'>Asset: <code>{ev.asset_id or '—'}</code> · "
        f"Classifier: <code>{ev.classifier_model}</code> · "
        f"Artifacts: {len(ev.artifacts)}</span>",
        unsafe_allow_html=True,
    )
    st.write("")

    # --- Techniques with LLM reasoning ---
    st.markdown("**Techniques**")
    for t in ev.techniques:
        with st.container(border=True):
            st.markdown(
                f"<code>{t.technique_id}</code> <b>{t.technique_name}</b>  ·  "
                f"tactic: <code>{t.tactic}</code>",
                unsafe_allow_html=True,
            )
            st.progress(t.confidence, text=f"confidence: {t.confidence:.2f}")
            if t.reasoning:
                st.markdown(
                    f"<span style='color:#94a3b8; font-size:0.9rem;'>"
                    f"<b>LLM reasoning:</b> <i>{t.reasoning}</i></span>",
                    unsafe_allow_html=True,
                )

    # --- Correlations involving this event ---
    st.markdown("**Correlations involving this event**")
    correlations = pipeline.storage.get_correlations_for_event(ev.event_id)
    if not correlations:
        st.caption("No correlations recorded.")
    else:
        rows = []
        for corr in sorted(correlations, key=lambda c: (-c.score, c.method)):
            other_id = (corr.event_b_id if corr.event_a_id == ev.event_id
                        else corr.event_a_id)
            other_ev = pipeline.storage.get_event(other_id)
            other_label = (
                f"{other_ev.timestamp.strftime('%H:%M:%S')} "
                f"{other_ev.domain} ("
                + ", ".join(t.technique_id for t in other_ev.techniques)
                + ")"
            ) if other_ev else str(other_id)[:8]
            rows.append({
                "Method":      corr.method.replace("_", " "),
                "Other event": other_label,
                "Score":       corr.score,
                "Δt (s)":      int(corr.delta_t_s),
            })
        st.dataframe(
            pd.DataFrame(rows),
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=1, format="%.2f"
                ),
            },
            hide_index=True,
            use_container_width=True,
        )

    # --- Raw JSON ---
    with st.expander("Raw event (JSON)"):
        # ev.raw es el dict original; lo serializamos
        try:
            raw_str = json.dumps(ev.raw, indent=2, default=str, ensure_ascii=False)
        except Exception:
            raw_str = str(ev.raw)
        st.code(raw_str, language="json")

    # --- Artifacts (si los hay) ---
    if ev.artifacts:
        with st.expander(f"Artifacts ({len(ev.artifacts)})"):
            for a in ev.artifacts:
                st.markdown(f"- <code>{a}</code>", unsafe_allow_html=True)


# Entry point cuando Streamlit ejecuta este script como página
show()
