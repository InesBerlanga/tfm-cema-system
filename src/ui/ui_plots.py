"""Plotly figures: timeline CEMA (dashboard) y chain graph vertical (incidents).

Dos funciones principales:
  - build_timeline_figure: dual-lane cyber/EW para visión global en Dashboard.
  - build_chain_graph_figure: grafo vertical con flujo top→bottom para Incident
    detail. Soporta ghost nodes para las top-3 predicciones del LLM.

El chain graph usa layout Sugiyama-style por niveles (longest path from source)
y posicionamiento por baricentro dentro de cada nivel para minimizar cruces.
"""

from __future__ import annotations

from typing import Optional
from uuid import UUID

import networkx as nx
import plotly.graph_objects as go

from chains import Chain
from schemas import ClassifiedEvent
from ui_theme import COLORS


# ============================================================================
# Layout helper para el chain graph
# ============================================================================

def _compute_chain_layout(
    events_sorted: list[ClassifiedEvent],
    canonical_pairs: set[tuple[str, str]],
) -> tuple[dict[str, tuple[float, float]], dict[str, int], int]:
    """Layout vertical estilo Sugiyama. Y por nivel topológico, X por baricentro.

    Devuelve:
      - positions: dict event_id_str -> (x, y)
      - levels: dict event_id_str -> int (nivel topológico)
      - max_level: máximo nivel observado
    """
    G = nx.DiGraph()
    for ev in events_sorted:
        G.add_node(str(ev.event_id))
    for (a, b) in canonical_pairs:
        G.add_edge(a, b)

    # 1) Nivel topológico = longest path desde los sources (orden de profundidad
    #    en el DAG). Si dos eventos comparten profundidad acaban en la misma
    #    fila visual, replicando el aspecto tree-like del mockup.
    levels: dict[str, int] = {}
    for node in nx.topological_sort(G):
        preds = list(G.predecessors(node))
        levels[node] = (max(levels[p] for p in preds) + 1) if preds else 0
    max_level = max(levels.values()) if levels else 0

    # 2) Agrupar nodos por nivel y asignar posiciones X mediante heurística
    #    de baricentro: cada nodo se centra cerca de la X promedio de sus
    #    predecesores. Cuando varios nodos coinciden en nivel, se reparten.
    nodes_by_level: dict[int, list[str]] = {}
    for node, lvl in levels.items():
        nodes_by_level.setdefault(lvl, []).append(node)

    positions: dict[str, tuple[float, float]] = {}
    X_SPACING = 1.6  # separación horizontal entre nodos del mismo nivel

    for level in range(max_level + 1):
        nodes = nodes_by_level.get(level, [])
        if not nodes:
            continue

        if level == 0:
            # Sources: reparto uniforme alrededor de X=0
            n = len(nodes)
            for i, node in enumerate(nodes):
                x = (i - (n - 1) / 2) * X_SPACING
                positions[node] = (x, 0.0)
        else:
            # Baricentro: X promedio de predecesores
            barys = []
            for node in nodes:
                preds = [p for p in G.predecessors(node) if p in positions]
                bary = (sum(positions[p][0] for p in preds) / len(preds)
                        if preds else 0.0)
                barys.append((node, bary))

            # Ordenar por baricentro, distribuir alrededor de la media
            barys.sort(key=lambda nb: nb[1])
            n = len(barys)
            if n == 1:
                node, bary = barys[0]
                positions[node] = (bary, -level)
            else:
                mean_bary = sum(b for _, b in barys) / n
                for i, (node, _) in enumerate(barys):
                    x = mean_bary + (i - (n - 1) / 2) * X_SPACING
                    positions[node] = (x, -level)

    return positions, levels, max_level


# ============================================================================
# Chain graph (Incidents detail) — vertical, mixed flow, ghost predictions
# ============================================================================

def compute_main_path(chain: Chain) -> set[tuple[str, str]]:
    """Para cada evento (en orden cronológico), conserva ÚNICAMENTE su
    arista entrante más fuerte hacia un evento anterior.

    El conjunto resultante es un bosque (un árbol por cada evento "fuente"
    sin predecesores correlacionados). Cada nodo no-fuente tiene exactamente
    un padre: el evento previo que el sistema considera causa más fuerte.

    Devuelve aristas canónicas como (older_id_str, newer_id_str).
    """
    events_sorted = sorted(chain.events, key=lambda e: e.timestamp)
    if len(events_sorted) <= 1:
        return set()

    main_edges: set[tuple[str, str]] = set()
    for i, ev_b in enumerate(events_sorted[1:], start=1):
        best_edge: Optional[tuple[str, str]] = None
        best_strength = 0.0
        for ev_a in events_sorted[:i]:
            key = (ev_a.event_id, ev_b.event_id)
            strength = chain.pair_strengths.get(key, 0.0)
            if strength > best_strength:
                best_strength = strength
                best_edge = (str(ev_a.event_id), str(ev_b.event_id))
        if best_edge is not None:
            main_edges.add(best_edge)
    return main_edges


def build_chain_graph_figure(
    chain: Chain,
    predictions: Optional[list] = None,  # list[TechniquePrediction]; top 3 se muestran
    show_all_edges: bool = False,
) -> go.Figure:
    """Grafo vertical de una cadena. Top = evento más antiguo. Nodos coloreados
    por dominio.

    Por defecto solo se dibuja el **camino principal**: para cada evento,
    su arista entrante más fuerte (forma un árbol/bosque). Esto evita el ruido
    visual de múltiples aristas paralelas por par.

    Si ``show_all_edges=True``, las aristas secundarias (resto de
    correlaciones del par) se superponen al árbol en estilo discreto
    (línea fina punteada, opacidad baja).

    Aristas cross-dominio van en rojo prominente; el resto, en gris neutro.
    Las top-3 predicciones se pintan como ghost nodes translúcidos al final."""
    fig = go.Figure()

    if not chain.events:
        fig.add_annotation(
            text="No events in this chain",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color=COLORS["text_muted"]),
        )
        fig.update_layout(
            height=300,
            plot_bgcolor=COLORS["bg_deep"],
            paper_bgcolor=COLORS["bg_deep"],
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
        )
        return fig

    events_sorted = sorted(chain.events, key=lambda e: e.timestamp)
    event_by_id = {str(ev.event_id): ev for ev in events_sorted}
    event_label = {str(ev.event_id): f"E{i+1}"
                   for i, ev in enumerate(events_sorted)}
    event_index = {eid: i for i, eid in enumerate(event_by_id.keys())}

    # Canonical pairs (older → newer)
    canonical_pairs: set[tuple[str, str]] = set()
    for corr in chain.correlations:
        a, b = str(corr.event_a_id), str(corr.event_b_id)
        if event_index[a] < event_index[b]:
            canonical_pairs.add((a, b))
        else:
            canonical_pairs.add((b, a))

    # Pair strengths (clave canónica = (older UUID, newer UUID))
    def get_strength(a: str, b: str) -> float:
        for (ua, ub), s in chain.pair_strengths.items():
            if {str(ua), str(ub)} == {a, b}:
                return s
        return 0.0

    # ===== Camino principal: aristas que forman el árbol =====
    # Para cada evento, su predecesor más fuerte (greedy). Usadas para layout
    # y dibujadas en estilo prominente. El resto de aristas son "secundarias".
    main_edges = compute_main_path(chain)
    secondary_edges = canonical_pairs - main_edges

    # Layout: SOLO con las aristas del camino principal — así la topología
    # visual es siempre un árbol limpio, sin saltos producidos por correlaciones
    # transversales que oscurecerían el flujo causal.
    positions, levels, max_level = _compute_chain_layout(events_sorted, main_edges)

    # Si por filtros aplicados algún nodo quedó fuera del layout (aislado en el
    # subgrafo del camino principal), le damos posición por defecto: nuevo nivel
    # al final del bosque, X centrado.
    for eid in event_by_id:
        if eid not in positions:
            positions[eid] = (0.0, -(max_level + 1))
            levels[eid] = max_level + 1
    max_level = max(levels.values()) if levels else 0

    # Dimensiones de las cajas (en unidades de datos)
    BOX_W = 1.45
    BOX_H = 0.78

    # =================  Aristas (dibujadas PRIMERO, debajo de los nodos)  =====
    def _draw_edge(a: str, b: str, primary: bool) -> None:
        """Dibuja una arista (línea + flecha). `primary` controla el estilo:
        prominente para el camino principal, sutil (punteada, opacidad baja)
        para correlaciones secundarias."""
        ev_a, ev_b = event_by_id[a], event_by_id[b]
        x0, y0 = positions[a]
        x1, y1 = positions[b]

        strength = get_strength(a, b)
        is_cross_dom = ev_a.domain != ev_b.domain

        color = COLORS["edge_cross_domain"] if is_cross_dom else COLORS["edge_neutral"]

        # Reglas que dispararon para este par (para hover)
        pair_corrs = [
            c for c in chain.correlations
            if {str(c.event_a_id), str(c.event_b_id)} == {a, b}
        ]
        rules_summary = "<br>".join(
            f"  • {c.method.replace('_', ' ')} (score {c.score:.2f})"
            for c in sorted(pair_corrs, key=lambda c: -c.score)
        )
        kind_label = "<b>main path</b>" if primary else "<i>secondary</i>"
        hover_text = (
            f"<b>{event_label[a]} → {event_label[b]}</b> · {kind_label}<br>"
            f"Aggregate strength: <b>{strength:.3f}</b><br>"
            f"{'<b>Cross-domain</b><br>' if is_cross_dom else ''}"
            f"Rules ({len(pair_corrs)}):<br>{rules_summary}"
        )

        if primary:
            # Grosor proporcional a strength: 1.5px..5.5px; cross-dom +1px
            width = 1.5 + 4.0 * min(1.0, strength)
            if is_cross_dom:
                width += 1.0
            line_kwargs = dict(color=color, width=width)
            line_opacity = 1.0 if is_cross_dom else 0.9
            arrow_opacity = 0.95 if is_cross_dom else 0.75
            arrow_width = 1.1
        else:
            # Secundarias: discretas — punteadas, finas, semi-transparentes
            line_kwargs = dict(color=color, width=1.2, dash="dot")
            line_opacity = 0.45 if is_cross_dom else 0.30
            arrow_opacity = 0.45 if is_cross_dom else 0.30
            arrow_width = 0.8

        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode="lines",
            line=line_kwargs,
            hovertext=[hover_text, hover_text],
            hoverinfo="text",
            showlegend=False,
            opacity=line_opacity,
        ))
        fig.add_annotation(
            x=x1, y=y1, ax=x0, ay=y0,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True,
            arrowhead=2, arrowsize=0.9, arrowwidth=arrow_width,
            arrowcolor=color,
            opacity=arrow_opacity,
            standoff=22,
        )

    # Secundarias primero (quedan debajo del camino principal visualmente)
    if show_all_edges:
        for (a, b) in secondary_edges:
            _draw_edge(a, b, primary=False)

    for (a, b) in main_edges:
        _draw_edge(a, b, primary=True)

    # =================  Nodos (encima de las aristas)  =================
    for eid, ev in event_by_id.items():
        x, y = positions[eid]
        color = COLORS["cyber"] if ev.domain == "cyber" else COLORS["ew"]

        # Caja
        fig.add_shape(
            type="rect",
            x0=x - BOX_W / 2, x1=x + BOX_W / 2,
            y0=y - BOX_H / 2, y1=y + BOX_H / 2,
            fillcolor=color,
            line=dict(color=COLORS["bg_deep"], width=2),
            layer="above",
        )

        # # Etiqueta dentro: "E1  T1190"
        # techs_str = ", ".join(t.technique_id for t in ev.techniques)
        # label = f"<b>{event_label[eid]}</b>  {techs_str}"
        # fig.add_annotation(
        #     x=x, y=y, text=label,
        #     showarrow=False,
        #     font=dict(size=11, family="JetBrains Mono, monospace", color="#0a0e1a"),
        # )
        
        # Técnica principal para mostrar dentro del nodo
        if ev.techniques:
            main_tech = ev.techniques[0]
            tech_id = main_tech.technique_id
            tech_name = main_tech.technique_name
            if len(ev.techniques) > 1:
                tech_name += f" (+{len(ev.techniques)-1})"
        else:
            tech_id = "NO_TECH"
            tech_name = "No technique"

        label = (
            f"<b>{event_label[eid]} · {tech_id}</b>"
            f"<br><span style='font-size:10px'>{tech_name}</span>"
        )

        fig.add_annotation(
            x=x,
            y=y,
            text=label,
            showarrow=False,
            align="center",
            xanchor="center",
            yanchor="middle",
            font=dict(
                size=11,
                family="JetBrains Mono, monospace",
                color=COLORS["text"],
            ),
        )

        # Trace invisible para hover detallado
        techs_hover = "<br>".join(
            f"• <b>{t.technique_id}</b> {t.technique_name} "
            f"({t.tactic}, conf {t.confidence:.2f})"
            for t in ev.techniques
        )
        hover_text = (
            f"<b>{event_label[eid]} — {ev.domain.upper()}</b><br>"
            f"Time: {ev.timestamp.strftime('%H:%M:%S')}<br>"
            f"Asset: <b>{ev.asset_id or '—'}</b><br>"
            f"<br>{techs_hover}"
        )
        fig.add_trace(go.Scatter(
            x=[x], y=[y],
            mode="markers",
            marker=dict(size=40, opacity=0, color=color),
            hovertext=hover_text,
            hoverinfo="text",
            showlegend=False,
        ))

    # =================  Ghost nodes para predicciones (top-3)  =================
    ghost_count = 0
    gx_positions: list[float] = []  # necesario para incluirlos en el rango X del eje
    if predictions:
        top3 = predictions[:3]
        ghost_y = -(max_level + 1.2)
        n = len(top3)
        # gx_positions = [(i - (n - 1) / 2) * X_SPACING_GHOST for i in range(n)]
        all_chain_xs = [positions[eid][0] for eid in positions]
        center_x = (min(all_chain_xs) + max(all_chain_xs)) / 2 if all_chain_xs else 0.0
        gx_positions = [center_x + (i - (n - 1) / 2) * X_SPACING_GHOST for i in range(n)]
        
        # Los ghost nodes "salen" de los eventos del último nivel observado
        last_eids = [eid for eid, lvl in levels.items() if lvl == max_level]

        for i, pred in enumerate(top3):
            gx = gx_positions[i]
            gy = ghost_y
            ghost_color = COLORS["cyber"] if pred.domain == "cyber" else COLORS["ew"]

            # Edge punteado desde cada último nodo observado
            for last_eid in last_eids:
                lx, ly = positions[last_eid]
                fig.add_trace(go.Scatter(
                    x=[lx, gx], y=[ly, gy],
                    mode="lines",
                    line=dict(color=COLORS["edge_ghost"], width=1.3, dash="dot"),
                    hoverinfo="skip",
                    showlegend=False,
                    opacity=0.55,
                ))
                fig.add_annotation(
                    x=gx, y=gy, ax=lx, ay=ly,
                    xref="x", yref="y", axref="x", ayref="y",
                    showarrow=True,
                    arrowhead=2, arrowsize=0.8, arrowwidth=1.0,
                    arrowcolor=COLORS["edge_ghost"],
                    opacity=0.5,
                    standoff=22,
                )

            # Caja ghost (translúcida, borde punteado se simula con opacidad)
            fig.add_shape(
                type="rect",
                x0=gx - BOX_W / 2, x1=gx + BOX_W / 2,
                y0=gy - BOX_H / 2, y1=gy + BOX_H / 2,
                fillcolor=ghost_color,
                line=dict(color=COLORS["text_muted"], width=1.5),
                opacity=0.4,
                layer="above",
            )
            # Etiqueta: solo technique_id + technique_name, sin identificador de evento
            label = (
                f"<b>{pred.technique_id}</b>"
                f"<br><span style='font-size:10px'>{pred.technique_name}</span>"
            )
            fig.add_annotation(
                x=gx, y=gy, text=label,
                showarrow=False,
                align="center",
                xanchor="center",
                yanchor="middle",
                font=dict(size=11, family="JetBrains Mono, monospace",
                          color="#0a0e1a"),
                opacity=0.85,
            )
            # Probabilidad debajo
            fig.add_annotation(
                x=gx, y=gy - BOX_H / 2 - 0.18,
                text=f"<i>p = {pred.probability:.0%}</i>",
                showarrow=False,
                font=dict(size=10, color=COLORS["text_secondary"]),
            )
            # Hover detallado de la predicción
            pred_hover = (
                f"<b>PREDICTED — {pred.domain.upper()}</b><br>"
                f"<b>{pred.technique_id}</b> {pred.technique_name}<br>"
                f"Tactic: {pred.tactic}<br>"
                f"Probability: <b>{pred.probability:.0%}</b><br>"
                f"<br><i>{pred.reasoning}</i>"
            )
            fig.add_trace(go.Scatter(
                x=[gx], y=[gy],
                mode="markers",
                marker=dict(size=40, opacity=0),
                hovertext=pred_hover,
                hoverinfo="text",
                showlegend=False,
            ))
            ghost_count += 1

    # =================  Layout / ejes  =================
    y_min = -(max_level + (1.8 if ghost_count > 0 else 0.6))
    y_max = 0.6

    # Rango X dinámico — incluye ghost nodes para que sus anotaciones no se desplacen
    all_xs = [p[0] for p in positions.values()] + gx_positions
    if all_xs:
        x_min = min(all_xs) - 1.2
        x_max = max(all_xs) + 1.2
    else:
        x_min, x_max = -2, 2

    # Altura proporcional al número de niveles
    n_visual_rows = max_level + 1 + (1 if ghost_count > 0 else 0)
    height = max(400, 130 * n_visual_rows)

    fig.update_layout(
        plot_bgcolor=COLORS["bg_deep"],
        paper_bgcolor=COLORS["bg_deep"],
        showlegend=False,
        hovermode="closest",
        margin=dict(t=20, b=20, l=20, r=20),
        height=height,
        xaxis=dict(
            visible=False,
            range=[x_min, x_max],
            fixedrange=True,
        ),
        yaxis=dict(
            visible=False,
            range=[y_min, y_max],
            fixedrange=True,
        ),
    )
    return fig


# Separación horizontal entre ghost nodes (un poco más amplia que entre nodos
# reales para que se distingan visualmente como "fuera de la cadena observada")
X_SPACING_GHOST = 1.8


# ============================================================================
# Timeline CEMA (Dashboard) — dual-lane cyber/EW
# ============================================================================

def build_timeline_figure(chains: list[Chain]) -> go.Figure:
    """Timeline dual-lane: cyber arriba (y=1), EW abajo (y=0). Todos los eventos
    visibles de un vistazo. Las correlaciones se dibujan como líneas, coloreadas
    por método. Las cross-domain se dibujan más gruesas para destacar."""
    fig = go.Figure()

    all_events: dict[str, ClassifiedEvent] = {}
    for c in chains:
        for ev in c.events:
            all_events[str(ev.event_id)] = ev

    if not all_events:
        fig.add_annotation(
            text="No events to display. Load the demo scenario from the sidebar.",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(size=13, color=COLORS["text_muted"]),
        )
        fig.update_layout(
            height=280,
            plot_bgcolor=COLORS["bg_deep"],
            paper_bgcolor=COLORS["bg_deep"],
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            margin=dict(t=20, b=20, l=20, r=20),
        )
        return fig

    # Mapa de colores por método (para las aristas del timeline)
    method_color = {
        "kill_chain":        "#64748b",
        "asset_convergence": "#06b6d4",
        "shared_artifact":   "#10b981",
        "geo_proximity":     "#a855f7",
        "cross_domain":      COLORS["edge_cross_domain"],
    }
    method_order = ["kill_chain", "asset_convergence", "shared_artifact",
                    "geo_proximity", "cross_domain"]

    # --- Aristas primero ---
    corrs_by_method: dict[str, list] = {}
    for c in chains:
        for corr in c.correlations:
            corrs_by_method.setdefault(corr.method, []).append(corr)

    for method in method_order:
        corr_list = corrs_by_method.get(method, [])
        if not corr_list:
            continue
        xs, ys, hover_texts = [], [], []
        for corr in corr_list:
            ev_a = all_events.get(str(corr.event_a_id))
            ev_b = all_events.get(str(corr.event_b_id))
            if not ev_a or not ev_b:
                continue
            y_a = 1 if ev_a.domain == "cyber" else 0
            y_b = 1 if ev_b.domain == "cyber" else 0
            xs.extend([ev_a.timestamp, ev_b.timestamp, None])
            ys.extend([y_a, y_b, None])
            ht = (f"<b>{method.replace('_', ' ')}</b><br>"
                  f"score: {corr.score:.2f}<br>"
                  f"Δt: {int(corr.delta_t_s)}s")
            hover_texts.extend([ht, ht, None])

        is_cross = method == "cross_domain"
        fig.add_trace(go.Scatter(
            x=xs, y=ys,
            mode="lines",
            line=dict(color=method_color[method], width=4 if is_cross else 2),
            opacity=1.0 if is_cross else 0.55,
            name=method.replace("_", " "),
            hovertext=hover_texts,
            hoverinfo="text",
            legendgroup="rules",
            legendgrouptitle_text="rules",
        ))

    # --- Nodos por dominio ---
    def event_hover(ev: ClassifiedEvent) -> str:
        techs = "<br>".join(
            f"• <b>{t.technique_id}</b> {t.technique_name} ({t.tactic})"
            for t in ev.techniques
        )
        return (f"<b>{ev.domain.upper()} @ {ev.timestamp.strftime('%H:%M:%S')}</b><br>"
                f"Asset: <b>{ev.asset_id or '—'}</b><br>{techs}")

    cyber_evs = [ev for ev in all_events.values() if ev.domain == "cyber"]
    ew_evs    = [ev for ev in all_events.values() if ev.domain == "ew"]

    if cyber_evs:
        fig.add_trace(go.Scatter(
            x=[ev.timestamp for ev in cyber_evs],
            y=[1] * len(cyber_evs),
            mode="markers",
            marker=dict(
                size=14, color=COLORS["cyber"], symbol="circle",
                line=dict(color=COLORS["bg_deep"], width=2),
            ),
            name="cyber",
            hovertext=[event_hover(ev) for ev in cyber_evs],
            hoverinfo="text",
            legendgroup="dom",
            legendgrouptitle_text="domain",
        ))
    if ew_evs:
        fig.add_trace(go.Scatter(
            x=[ev.timestamp for ev in ew_evs],
            y=[0] * len(ew_evs),
            mode="markers",
            marker=dict(
                size=14, color=COLORS["ew"], symbol="diamond",
                line=dict(color=COLORS["bg_deep"], width=2),
            ),
            name="ew",
            hovertext=[event_hover(ev) for ev in ew_evs],
            hoverinfo="text",
            legendgroup="dom",
        ))

    fig.update_layout(
        plot_bgcolor=COLORS["bg_deep"],
        paper_bgcolor=COLORS["bg_deep"],
        yaxis=dict(
            tickmode="array",
            tickvals=[0, 1],
            ticktext=["EW", "cyber"],
            range=[-0.5, 1.5],
            showgrid=True,
            gridcolor=COLORS["border"],
            tickfont=dict(family="JetBrains Mono, monospace", size=11,
                         color=COLORS["text_secondary"]),
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor=COLORS["border"],
            tickfont=dict(size=10, color=COLORS["text_muted"]),
        ),
        height=320,
        margin=dict(t=20, b=40, l=50, r=120),
        showlegend=True,
        legend=dict(
            orientation="v", yanchor="top", y=1,
            xanchor="left", x=1.02,
            font=dict(size=10, color=COLORS["text_secondary"]),
            groupclick="togglegroup",
        ),
        hovermode="closest",
        hoverlabel=dict(bgcolor=COLORS["bg_surface"], bordercolor=COLORS["border"]),
    )
    return fig