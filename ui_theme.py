"""Theme centralizado: paleta, CSS personalizado, helpers de formato.

Importa desde aquí cualquier color o helper que necesites en las views.
"""

from __future__ import annotations

from datetime import datetime, timezone


# ============================================================================
# Paleta — tono SOC militar oscuro
# ============================================================================

COLORS = {
    # Fondos
    "bg_deep":    "#0a0e1a",  # base profunda
    "bg_surface": "#141b2d",  # cards, sidebar
    "border":     "#1f2937",  # bordes sutiles

    # Texto
    "text":           "#e5e7eb",
    "text_secondary": "#94a3b8",
    "text_muted":     "#64748b",

    # Dominio
    "cyber": "#60a5fa",  # azul brillante
    "ew":    "#fb923c",  # naranja cálido

    # Estado / alertas
    "alert":   "#ef4444",  # rojo — cross-domain crítico
    "warning": "#f59e0b",  # ámbar
    "success": "#10b981",  # verde

    # Grafo
    "edge_neutral":      "#475569",  # gris intra-dominio
    "edge_cross_domain": "#ef4444",  # rojo cross-dominio (prominente)
    "edge_ghost":        "#64748b",  # gris muted para predicciones
}


# ============================================================================
# CSS personalizado — se inyecta una vez por página vía inject_css(st)
# ============================================================================

CSS = """
<style>
/* --- Monospace para IDs técnicos, códigos --- */
code, .code, kbd {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Mono', 'Consolas', monospace !important;
    font-size: 0.88em;
    background: rgba(96, 165, 250, 0.08);
    color: #93c5fd;
    padding: 1px 6px;
    border-radius: 3px;
    border: 1px solid rgba(96, 165, 250, 0.18);
}

/* --- Métricas estilo intelligence-dashboard --- */
[data-testid="stMetricLabel"] {
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 0.7rem !important;
    color: #94a3b8 !important;
    font-weight: 500;
}
[data-testid="stMetricValue"] {
    font-weight: 600;
    font-feature-settings: "tnum";
}
[data-testid="stMetricDelta"] {
    font-size: 0.75rem;
}

/* --- Pills/chips --- */
.pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-right: 6px;
    line-height: 1.5;
}
.pill-cyber       { background: rgba(96, 165, 250, 0.15); color: #93c5fd; border: 1px solid rgba(96, 165, 250, 0.3); }
.pill-ew          { background: rgba(251, 146, 60, 0.15); color: #fdba74; border: 1px solid rgba(251, 146, 60, 0.3); }
.pill-cross       { background: rgba(239, 68, 68, 0.12); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.35); }
.pill-reactive    { background: rgba(239, 68, 68, 0.10); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.30); }
.pill-preventive  { background: rgba(96, 165, 250, 0.10); color: #93c5fd; border: 1px solid rgba(96, 165, 250, 0.30); }
.pill-neutral     { background: rgba(148, 163, 184, 0.10); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.25); }

/* --- Sidebar section header --- */
.sb-section {
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.7rem;
    color: #94a3b8;
    margin: 1.4rem 0 0.5rem;
    font-weight: 600;
    border-bottom: 1px solid #1f2937;
    padding-bottom: 0.3rem;
}

/* --- Incident card --- */
.incident-card {
    background: #141b2d;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 10px;
    transition: border-color 0.15s ease;
}
.incident-card:hover {
    border-color: #3b82f6;
}
.incident-card-id {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.05rem;
    font-weight: 600;
    color: #e5e7eb;
}
.incident-card-meta {
    color: #94a3b8;
    font-size: 0.82rem;
    margin-top: 4px;
    line-height: 1.7;
}

/* --- Headers más sobrios --- */
h1 { font-weight: 600; letter-spacing: -0.01em; }
h2 { font-weight: 600; letter-spacing: -0.005em; font-size: 1.4rem; }
h3 { font-weight: 600; font-size: 1.1rem; color: #cbd5e1; }
h4 {
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
}

/* --- Botones más sobrios --- */
button[kind="primary"], button[kind="secondary"] {
    border-radius: 4px !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
    font-weight: 500 !important;
}

/* --- Reducir chrome de Streamlit --- */
header[data-testid="stHeader"] { background: transparent; height: 0; }
[data-testid="stToolbar"] { display: none; }

/* --- Containers con borde sutil --- */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 6px !important;
}

/* --- Predicción con ghost look --- */
.ghost-box {
    background: rgba(20, 27, 45, 0.6);
    border: 1px dashed #475569;
    border-radius: 4px;
    padding: 10px 12px;
    margin-bottom: 8px;
    opacity: 0.92;
}

/* --- Detail section dividers --- */
.section-divider {
    border-top: 1px solid #1f2937;
    margin: 1.4rem 0 1rem;
    padding-top: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.72rem;
    color: #94a3b8;
    font-weight: 600;
}
</style>
"""


def inject_css(st_module) -> None:
    """Inyecta el CSS personalizado. Llamar una vez al inicio de cada view."""
    st_module.markdown(CSS, unsafe_allow_html=True)


# ============================================================================
# Helpers de formato
# ============================================================================

def domain_pill(domain: str) -> str:
    """HTML chip de dominio (cyber/ew)."""
    cls = "pill-cyber" if domain == "cyber" else "pill-ew"
    return f'<span class="pill {cls}">{domain}</span>'


def cross_domain_pill() -> str:
    return '<span class="pill pill-cross">cross-domain</span>'


def neutral_pill(text: str) -> str:
    return f'<span class="pill pill-neutral">{text}</span>'


def code_chip(text: str) -> str:
    """Chip monospace inline."""
    return f"<code>{text}</code>"


def time_ago_str(when: datetime) -> str:
    """'X ago' relativo al momento actual."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - when
    seconds = max(0, delta.total_seconds())
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds / 3600)}h ago"
    return f"{int(seconds / 86400)}d ago"
