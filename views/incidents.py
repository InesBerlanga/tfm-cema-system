"""Incidents view: cadenas tratadas como incidentes (casos).

Dos modos:
  - Si no hay incidente seleccionado: lista de incident cards.
  - Si hay incidente seleccionado: detalle completo (grafo vertical hideable,
    eventos, correlaciones, predicciones bajo demanda, contramedidas).
"""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from app_state import get_filters, get_pipeline
from chains import Chain
from ui_data import build_correlations_df, get_filtered_chains
from ui_plots import build_chain_graph_figure
from ui_theme import (
    COLORS,
    code_chip,
    cross_domain_pill,
    domain_pill,
    inject_css,
    neutral_pill,
    time_ago_str,
)


def show() -> None:
    inject_css(st)
    pipeline = get_pipeline()
    filters = get_filters()
    chains = get_filtered_chains(pipeline, **filters)

    # ¿Detalle o lista?
    selected_id = st.session_state.get("selected_chain_id")
    selected_chain = None
    if selected_id:
        selected_chain = next((c for c in chains if c.chain_id == selected_id), None)

    if selected_chain is None:
        # La cadena seleccionada ya no pasa filtros (o no había selección):
        # mostramos la lista
        _render_list(chains)
    else:
        _render_detail(selected_chain, pipeline)


# ============================================================================
# Lista de incidentes
# ============================================================================

def _render_list(chains: list[Chain]) -> None:
    st.title("Incidents")
    st.caption(f"{len(chains)} incident(s) match the current filters")

    if not chains:
        st.info("No incidents match the current filters. Adjust strength threshold, "
                "domain selection, or load the demo scenario from the sidebar.")
        return

    # Ordenadas por strength descendente
    sorted_chains = sorted(chains, key=lambda c: -c.total_strength)

    for c in sorted_chains:
        # Renderizamos cada incidente como una "card" en HTML + botón Streamlit
        # debajo. Streamlit no permite HTML interactivo, así que el botón vive
        # por separado pero visualmente alineado.
        pills = ""
        for d in sorted(c.domains):
            pills += domain_pill(d)
        if c.is_cross_domain:
            pills += cross_domain_pill()
        pills += neutral_pill(f"strength {c.total_strength:.2f}")

        tactics_str = ", ".join(sorted(c.tactics)) if c.tactics else "—"
        assets_str = ", ".join(f"<code>{a}</code>" for a in sorted(c.assets)) or "—"

        card_html = f"""
        <div class="incident-card">
          <div class="incident-card-id">{c.chain_id[:8]}</div>
          <div style="margin: 6px 0 2px 0;">{pills}</div>
          <div class="incident-card-meta">
            Started <b>{time_ago_str(c.start_ts)}</b> ·
            <b>{c.event_count}</b> events ·
            duration <b>{int(c.duration_s)}s</b> ·
            <b>{c.pair_count}</b> correlated pairs<br>
            Assets: {assets_str}<br>
            Tactics: <i>{tactics_str}</i>
          </div>
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)

        # Botón para abrir el detalle (alineado debajo de la card)
        col_btn, _ = st.columns([1, 3])
        if col_btn.button("Open detail", key=f"open_{c.chain_id}", type="primary"):
            st.session_state["selected_chain_id"] = c.chain_id
            st.rerun()
        st.write("")  # spacer


# ============================================================================
# Detalle de incidente
# ============================================================================

def _render_detail(chain: Chain, pipeline) -> None:
    # Header con "back" y título
    col_back, col_title = st.columns([1, 5])
    if col_back.button("← Back to list", key="back_to_list"):
        st.session_state.pop("selected_chain_id", None)
        st.rerun()
    col_title.title(f"Incident {chain.chain_id[:8]}")

    # Pills row
    pills = ""
    for d in sorted(chain.domains):
        pills += domain_pill(d)
    if chain.is_cross_domain:
        pills += cross_domain_pill()
    st.markdown(pills, unsafe_allow_html=True)
    st.write("")

    # KPI strip
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Events", chain.event_count)
    m2.metric("Pairs", chain.pair_count)
    m3.metric("Duration", f"{int(chain.duration_s)}s")
    m4.metric("Strength", f"{chain.total_strength:.2f}")
    m5.metric("Assets", len(chain.assets))
    m6.metric("Tactics", len(chain.tactics))

    # ============================================================  Chain graph
    st.markdown('<div class="section-divider">Chain graph</div>',
                unsafe_allow_html=True)

    show_graph = st.toggle("Show graph", value=True, key=f"show_graph_{chain.chain_id}")

    if show_graph:
        # Recuperamos predicciones cacheadas si las hay (para los ghost nodes)
        predictions_cache = st.session_state.setdefault("predictions", {})
        cached_pred = predictions_cache.get(chain.chain_id)
        ghost_preds = cached_pred.predictions[:3] if cached_pred else None

        fig = build_chain_graph_figure(chain, predictions=ghost_preds)
        st.plotly_chart(fig, use_container_width=True)

        if ghost_preds:
            st.caption(f"Showing top {len(ghost_preds)} predicted technique(s) "
                       f"as ghost nodes below the chain. See full list in "
                       f"the Predictions panel.")

    # ============================================================  Events table
    st.markdown('<div class="section-divider">Events</div>',
                unsafe_allow_html=True)

    events_sorted = sorted(chain.events, key=lambda e: e.timestamp)
    events_rows = []
    for i, ev in enumerate(events_sorted, start=1):
        events_rows.append({
            "#":          f"E{i}",
            "Time":       ev.timestamp.strftime("%H:%M:%S"),
            "Domain":     ev.domain,
            "Techniques": ", ".join(t.technique_id for t in ev.techniques),
            "Tactics":    ", ".join(sorted({t.tactic for t in ev.techniques})),
            "Confidence": max((t.confidence for t in ev.techniques), default=0),
            "Asset":      ev.asset_id or "—",
        })
    st.dataframe(
        pd.DataFrame(events_rows),
        column_config={
            "Confidence": st.column_config.ProgressColumn(
                "Confidence", min_value=0, max_value=1, format="%.2f"
            ),
        },
        hide_index=True,
        use_container_width=True,
    )

    # ============================================================  Correlations
    st.markdown('<div class="section-divider">Correlations (raw breakdown)</div>',
                unsafe_allow_html=True)
    corr_df = build_correlations_df(chain)
    if corr_df.empty:
        st.caption("No correlations recorded for this chain.")
    else:
        st.dataframe(
            corr_df,
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=1, format="%.2f"
                ),
            },
            hide_index=True,
            use_container_width=True,
        )

    # ===================================  Predictions + Countermeasures (2 col)
    col_pred, col_cm = st.columns(2)

    _render_predictions(col_pred, chain, pipeline)
    _render_countermeasures(col_cm, chain, pipeline)


def _render_predictions(container, chain: Chain, pipeline) -> None:
    """Panel de predicciones (bajo demanda con botón)."""
    with container:
        st.markdown('<div class="section-divider">Predictions</div>',
                    unsafe_allow_html=True)

        predictions_cache = st.session_state.setdefault("predictions", {})
        cached_pred = predictions_cache.get(chain.chain_id)

        col_a, col_b = st.columns([2, 1])
        if col_a.button("Run LLM prediction",
                        key=f"predict_{chain.chain_id}",
                        type="primary",
                        use_container_width=True):
            with st.spinner("Calling LLM…"):
                try:
                    pred = pipeline.predictor.predict(chain, max_predictions=5)
                    predictions_cache[chain.chain_id] = pred
                    cached_pred = pred
                    st.rerun()
                except Exception as e:
                    st.error(f"Prediction failed: {type(e).__name__}: {e}")

        if cached_pred is not None and col_b.button(
            "Clear", key=f"clear_pred_{chain.chain_id}"
        ):
            predictions_cache.pop(chain.chain_id, None)
            st.rerun()

        if cached_pred is None:
            st.caption("Press the button to ask the LLM for plausible "
                       "continuations of this chain. Top 3 predictions will "
                       "appear as ghost nodes in the chain graph above.")
            return

        if not cached_pred.predictions:
            st.warning("The LLM did not return valid predictions.")
            return

        if cached_pred.overall_reasoning:
            st.markdown(f"<i>{cached_pred.overall_reasoning}</i>",
                        unsafe_allow_html=True)
            st.write("")

        for i, p in enumerate(cached_pred.predictions, start=1):
            kind_mark = " · ghost" if i <= 3 else ""
            pill = domain_pill(p.domain)
            with st.container(border=True):
                st.markdown(
                    f"{pill}<code>{p.technique_id}</code> "
                    f"<b>{p.technique_name}</b>{kind_mark}",
                    unsafe_allow_html=True,
                )
                st.progress(p.probability,
                            text=f"p = {p.probability:.0%}  ·  tactic: {p.tactic}")
                st.caption(p.reasoning)


def _render_countermeasures(container, chain: Chain, pipeline) -> None:
    """Panel de contramedidas (lookup, opcionalmente con predichas)."""
    with container:
        st.markdown('<div class="section-divider">Countermeasures</div>',
                    unsafe_allow_html=True)

        predictions_cache = st.session_state.setdefault("predictions", {})
        cached_pred = predictions_cache.get(chain.chain_id)

        include_pred = st.checkbox(
            "Include predicted techniques (preventive)",
            value=False,
            key=f"cm_incl_{chain.chain_id}",
            disabled=cached_pred is None,
            help="Include LLM-predicted continuations in the lookup. "
                 "Requires Predictions to have been run.",
        )

        preds = cached_pred.predictions if (include_pred and cached_pred) else None
        rec = pipeline.recommender.recommend(chain, predictions=preds)

        if not rec.matches:
            st.caption("No countermeasures cataloged for the techniques in this chain.")
            return

        # Summary chips
        chips = (
            f"<span class='pill pill-neutral'>{rec.total_matches} total</span>"
            f"<span class='pill pill-reactive'>{len(rec.reactive_matches)} reactive</span>"
            f"<span class='pill pill-preventive'>{len(rec.preemptive_matches)} preventive</span>"
        )
        st.markdown(chips, unsafe_allow_html=True)
        st.write("")

        for m in rec.matches[:10]:
            cm = m.countermeasure
            kind_pill = (
                "<span class='pill pill-preventive'>preventive</span>"
                if m.is_preemptive_only else
                "<span class='pill pill-reactive'>reactive</span>"
            )
            cover_str = ", ".join(
                f"<code>{tc.technique_id}</code>" for tc in m.covers
            )
            with st.container(border=True):
                st.markdown(
                    f"{domain_pill(cm.domain)}{kind_pill}<b>{cm.name}</b>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<span style='color:#94a3b8; font-size:0.85rem;'>"
                    f"priority <b>{m.priority:.1f}</b>  ·  covers: {cover_str}"
                    f"{'  ·  <code>' + cm.top_level + '</code>' if cm.top_level else ''}"
                    f"</span>",
                    unsafe_allow_html=True,
                )

        if rec.techniques_with_no_match:
            with st.expander(
                f"{len(rec.techniques_with_no_match)} technique(s) without "
                f"catalog defense"
            ):
                for tc in rec.techniques_with_no_match:
                    st.markdown(
                        f"- {domain_pill(tc.domain)}<code>{tc.technique_id}</code> "
                        f"{tc.technique_name} ({tc.source})",
                        unsafe_allow_html=True,
                    )


# Entry point cuando Streamlit ejecuta este script como página
show()
