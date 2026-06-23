"""Data layer para la UI: demo loader, filtros, builders de DataFrames.

Centraliza el acceso a la BD a través del pipeline y aplica los filtros
del sidebar para que las views no tengan que repetir esa lógica.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

import pandas as pd

from chains import Chain
from pipeline import Pipeline
from schemas import ClassifiedEvent, TechniqueAssignment
from ui_theme import time_ago_str


# ============================================================================
# Demo loader (NOW-relative para que los filtros temporales funcionen)
# ============================================================================

def clear_database(pipeline: Pipeline) -> None:
    """Vacía las tres tablas. Mantiene el schema."""
    with sqlite3.connect(pipeline.storage.db_path) as conn:
        conn.execute("DELETE FROM correlations")
        conn.execute("DELETE FROM event_techniques")
        conn.execute("DELETE FROM classified_events")


def reset_and_load_demo(pipeline: Pipeline) -> int:
    """Vacía BD y carga los 6 eventos del escenario CEMA, anclados a NOW
    (los timestamps son relativos al momento actual menos 14 minutos)
    para que el filtro de time-window funcione."""
    clear_database(pipeline)

    t0 = datetime.now(timezone.utc) - timedelta(minutes=14)

    def mk(domain, dt_min, techs, **kwargs):
        return ClassifiedEvent(
            event_id=uuid4(),
            timestamp=t0 + timedelta(minutes=dt_min),
            domain=domain,
            techniques=[
                TechniqueAssignment(
                    technique_id=tid, technique_name=name,
                    tactic=tactic, confidence=conf,
                    reasoning=f"Synthetic demo classification. The classifier mapped "
                              f"the observed event signature to {tid} based on context "
                              f"({tactic} tactic, observed in {domain} domain).",
                )
                for tid, name, tactic, conf in techs
            ],
            classifier_model="demo",
            **kwargs,
        )

    events = [
        mk("ew", 0,
           [("TEW01", "Electromagnetic Reconnaissance", "detect", 0.85)],
           asset_id="GPS_L1", location=(40.4168, -3.7038)),
        mk("ew", 2,
           [("TEW03", "Direction Finding", "exploit", 0.80)],
           asset_id="GPS_L1", location=(40.4180, -3.7050)),
        mk("cyber", 5,
           [("T1190", "Exploit Public-Facing Application", "initial-access", 0.78)],
           asset_id="NAV-CTRL-01", user_id="alice.operator",
           artifacts=["ip:185.220.101.42", "user:alice.operator"]),
        mk("cyber", 7,
           [("T1071", "Application Layer Protocol", "command-and-control", 0.90),
            ("T1498", "Network Denial of Service", "impact", 0.78)],
           asset_id="NAV-CTRL-01", user_id="alice.operator",
           artifacts=["ip:185.220.101.42", "user:alice.operator"]),
        mk("ew", 12,
           [("TEW06.2", "Barrage Jamming", "degrade-disrupt", 0.92)],
           asset_id="GPS_L1", location=(40.4172, -3.7042)),
        mk("cyber", 14,
           [("T1078", "Valid Accounts", "persistence", 0.82)],
           asset_id="SRV-DB-01", user_id="alice.operator",
           artifacts=["user:alice.operator"]),
    ]
    for ev in events:
        pipeline.process_classified(ev)
    return len(events)


# ============================================================================
# Filter helpers
# ============================================================================

def time_window_cutoff(window: str) -> Optional[datetime]:
    """Cutoff inferior según el time window seleccionado, o None para 'all'."""
    if window == "all":
        return None
    deltas = {"1h": 1, "6h": 6, "24h": 24}
    hours = deltas.get(window, 24)
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def get_filtered_chains(
    pipeline: Pipeline,
    domains: list[str],
    min_strength: float,
    min_events: int,
    time_window: str,
) -> list[Chain]:
    """Extrae cadenas y aplica filtros de dominio + time window.

    Semántica del filtro de dominio: LENIENT. Una cadena se muestra si tiene
    al menos un evento en alguno de los dominios filtrados. Una cross-domain
    se sigue mostrando si el filtro incluye cyber O ew.
    """
    chains = pipeline.chain_extractor.extract(
        min_pair_strength=min_strength,
        min_events=min_events,
    )

    cutoff = time_window_cutoff(time_window)
    domain_set = set(domains)

    result = []
    for c in chains:
        if not (c.domains & domain_set):
            continue
        if cutoff is not None and c.end_ts < cutoff:
            continue
        result.append(c)
    return result


def get_filtered_events(
    pipeline: Pipeline,
    domains: list[str],
    time_window: str,
) -> list[ClassifiedEvent]:
    """Devuelve eventos aplicando filtros de dominio y time-window."""
    cutoff = time_window_cutoff(time_window)

    with sqlite3.connect(pipeline.storage.db_path) as conn:
        conn.row_factory = sqlite3.Row
        clauses = []
        params: list = []
        if cutoff is not None:
            clauses.append("timestamp >= ?")
            params.append(cutoff.isoformat())
        if domains and len(domains) < 2:
            placeholders = ",".join(["?"] * len(domains))
            clauses.append(f"domain IN ({placeholders})")
            params.extend(domains)
        query = "SELECT event_id FROM classified_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp DESC"
        rows = conn.execute(query, params).fetchall()

    events = []
    for row in rows:
        ev = pipeline.storage.get_event(UUID(row["event_id"]))
        if ev is not None:
            events.append(ev)
    return events


# ============================================================================
# Table builders
# ============================================================================

def build_ranking_df(chains: list[Chain]) -> pd.DataFrame:
    """Para la tabla de cadenas en Dashboard / Incidents."""
    rows = []
    for c in chains:
        rows.append({
            "Chain":     c.chain_id[:8],
            "Started":   time_ago_str(c.start_ts),
            "Duration":  f"{int(c.duration_s)}s",
            "Events":    c.event_count,
            "Domains":   " + ".join(sorted(c.domains)),
            "Strength":  c.total_strength,
            "Assets":    len(c.assets),
            "Tactics":   ", ".join(sorted(c.tactics)) if c.tactics else "—",
        })
    return pd.DataFrame(rows)


def build_events_df(events: list[ClassifiedEvent]) -> pd.DataFrame:
    """Para la página de Events. Sin columna user (per spec)."""
    rows = []
    for ev in events:
        techs = ", ".join(t.technique_id for t in ev.techniques)
        tactics = ", ".join(sorted({t.tactic for t in ev.techniques}))
        max_conf = max((t.confidence for t in ev.techniques), default=0.0)
        rows.append({
            "Time":       ev.timestamp.strftime("%H:%M:%S"),
            "Date":       ev.timestamp.strftime("%Y-%m-%d"),
            "Domain":     ev.domain,
            "Techniques": techs,
            "Tactics":    tactics,
            "Confidence": max_conf,
            "Asset":      ev.asset_id or "—",
            "_event_id":  str(ev.event_id),  # internal, oculto en la vista
        })
    return pd.DataFrame(rows)


def build_correlations_df(chain: Chain) -> pd.DataFrame:
    """Desglose RAW de correlaciones de una cadena (una fila por regla disparada)."""
    rows = []
    event_label = {}
    for i, ev in enumerate(sorted(chain.events, key=lambda e: e.timestamp), start=1):
        event_label[str(ev.event_id)] = f"E{i}"

    for corr in sorted(chain.correlations, key=lambda c: (c.delta_t_s, c.method)):
        rows.append({
            "From":   event_label.get(str(corr.event_a_id), "?"),
            "To":     event_label.get(str(corr.event_b_id), "?"),
            "Method": corr.method.replace("_", " "),
            "Score":  corr.score,
            "Δt (s)": int(corr.delta_t_s),
        })
    return pd.DataFrame(rows)
