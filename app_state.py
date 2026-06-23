"""Estado compartido para las views.

- get_pipeline(): pipeline cacheado (una sola instancia por sesión)
- get_filters(): lee los valores actuales de los filtros del sidebar desde
                 session_state, devuelve un dict listo para pasar a las
                 funciones de ui_data.

Las views leen aquí en vez de manipular session_state directamente.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from pipeline import Pipeline


HERE = Path(__file__).parent
CONFIG_PATH = HERE / "config.json"


@st.cache_resource(show_spinner="Initializing pipeline...")
def get_pipeline() -> Pipeline:
    """Instancia única del Pipeline. Streamlit reusa este objeto entre
    reruns y entre páginas. La BD SQLite se accede abriendo conexiones
    nuevas, así que mutaciones son visibles sin invalidar el caché."""
    return Pipeline.from_config(CONFIG_PATH)


def get_filters() -> dict:
    """Devuelve los filtros del sidebar tal cual los necesita ui_data."""
    return {
        "domains":      st.session_state.get("flt_domains", ["cyber", "ew"]),
        "min_strength": st.session_state.get("flt_min_strength", 0.0),
        "min_events":   int(st.session_state.get("flt_min_events", 2)),
        "time_window":  st.session_state.get("flt_time_window", "all"),
    }
