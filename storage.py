"""Almacén SQLite para eventos clasificados y correlaciones.

Diseño:
- Una tabla `classified_events` con un evento por fila (datos no normalizados).
- Una tabla `event_techniques` 1:N con las técnicas asignadas a cada evento.
  Separar las técnicas en su propia tabla nos permite indexar por technique_id
  y hacer consultas "dame todos los eventos con técnica T1059" eficientemente.
- Una tabla `correlations` con un vínculo por fila entre dos eventos.

Los timestamps se almacenan como strings ISO 8601 con zona horaria (UTC).
SQLite no tiene tipo datetime nativo, pero comparar strings ISO ordena
cronológicamente sin problemas.

CAMBIO IMPORTANTE respecto a la versión anterior:
- classified_events lleva ahora columnas user_id, location_lat, location_lon,
  artifacts_json para soportar las reglas R4 (lateral movement), R5 (geo
  proximity) y R6 (shared artifact). Si tienes una BD anterior, bórrala y
  reinicia: SQLite no aplica los CREATE TABLE IF NOT EXISTS sobre tablas
  existentes.

Esta clase es sync (no async). Para el PoC es más que suficiente.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

from schemas import (
    ClassifiedEvent,
    Correlation,
    CorrelationMethod,
    TechniqueAssignment,
)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS classified_events (
    event_id          TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    domain            TEXT NOT NULL CHECK (domain IN ('cyber', 'ew')),
    asset_id          TEXT,
    user_id           TEXT,
    location_lat      REAL,
    location_lon      REAL,
    artifacts_json    TEXT,
    classifier_model  TEXT,
    classification_ts TEXT,
    raw_json          TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON classified_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_domain    ON classified_events(domain);
CREATE INDEX IF NOT EXISTS idx_events_asset     ON classified_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_user      ON classified_events(user_id);

CREATE TABLE IF NOT EXISTS event_techniques (
    event_id        TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT,
    tactic          TEXT,
    confidence      REAL,
    reasoning       TEXT,
    PRIMARY KEY (event_id, technique_id),
    FOREIGN KEY (event_id) REFERENCES classified_events(event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_techniques_event   ON event_techniques(event_id);
CREATE INDEX IF NOT EXISTS idx_techniques_tid     ON event_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_techniques_tactic  ON event_techniques(tactic);

CREATE TABLE IF NOT EXISTS correlations (
    correlation_id TEXT PRIMARY KEY,
    event_a_id     TEXT NOT NULL,
    event_b_id     TEXT NOT NULL,
    method         TEXT NOT NULL,
    score          REAL NOT NULL,
    delta_t_s      REAL NOT NULL,
    distance_m     REAL,
    metadata_json  TEXT,
    created_ts     TEXT NOT NULL,
    FOREIGN KEY (event_a_id) REFERENCES classified_events(event_id),
    FOREIGN KEY (event_b_id) REFERENCES classified_events(event_id),
    UNIQUE (event_a_id, event_b_id, method)
);

CREATE INDEX IF NOT EXISTS idx_corr_a      ON correlations(event_a_id);
CREATE INDEX IF NOT EXISTS idx_corr_b      ON correlations(event_b_id);
CREATE INDEX IF NOT EXISTS idx_corr_method ON correlations(method);
CREATE INDEX IF NOT EXISTS idx_corr_score  ON correlations(score);
"""


class CorrelationStore:
    """Acceso a la base SQLite. Crea/abre el archivo y expone CRUD básico."""

    def __init__(self, db_path: str | Path = "tfm_system.db"):
        self.db_path = str(db_path)
        self._init_schema()

    # ---------- inicialización ----------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    # ---------- eventos clasificados ----------

    def save_event(self, event: ClassifiedEvent) -> None:
        """Inserta o reemplaza un evento clasificado y sus técnicas."""
        loc_lat = event.location[0] if event.location else None
        loc_lon = event.location[1] if event.location else None
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO classified_events
                   (event_id, timestamp, domain, asset_id, user_id,
                    location_lat, location_lon, artifacts_json,
                    classifier_model, classification_ts, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(event.event_id),
                    event.timestamp.isoformat(),
                    event.domain,
                    event.asset_id,
                    event.user_id,
                    loc_lat,
                    loc_lon,
                    json.dumps(event.artifacts),
                    event.classifier_model,
                    event.classification_ts.isoformat(),
                    json.dumps(event.raw),
                ),
            )
            # Borrar técnicas existentes y re-insertar (atomicidad gracias a la txn)
            conn.execute(
                "DELETE FROM event_techniques WHERE event_id = ?",
                (str(event.event_id),),
            )
            if event.techniques:
                conn.executemany(
                    """INSERT INTO event_techniques
                       (event_id, technique_id, technique_name, tactic, confidence, reasoning)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    [
                        (
                            str(event.event_id),
                            t.technique_id,
                            t.technique_name,
                            t.tactic,
                            t.confidence,
                            t.reasoning,
                        )
                        for t in event.techniques
                    ],
                )

    def get_event(self, event_id: str | UUID) -> Optional[ClassifiedEvent]:
        """Recupera un evento por su ID, con sus técnicas asociadas."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM classified_events WHERE event_id = ?",
                (str(event_id),),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_event(conn, row)

    def get_events_in_window(
        self,
        center_time: datetime,
        window_seconds: float,
        domain: Optional[str] = None,
    ) -> list[ClassifiedEvent]:
        """Eventos con timestamp en [center_time − window, center_time].

        Si pasas domain='cyber' o 'ew' filtra por dominio.
        """
        from_time = center_time - timedelta(seconds=window_seconds)
        query = """SELECT * FROM classified_events
                   WHERE timestamp >= ? AND timestamp <= ?"""
        params: list = [from_time.isoformat(), center_time.isoformat()]
        if domain:
            query += " AND domain = ?"
            params.append(domain)
        query += " ORDER BY timestamp"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_event(conn, r) for r in rows]

    def _row_to_event(
        self, conn: sqlite3.Connection, row: sqlite3.Row
    ) -> ClassifiedEvent:
        """Convierte una fila + sus técnicas en un ClassifiedEvent."""
        techs = conn.execute(
            "SELECT * FROM event_techniques WHERE event_id = ?",
            (row["event_id"],),
        ).fetchall()
        # Reconstruir location si ambos campos están presentes
        location = None
        if row["location_lat"] is not None and row["location_lon"] is not None:
            location = (row["location_lat"], row["location_lon"])
        # Reconstruir artifacts (lista JSON o lista vacía si NULL)
        artifacts_raw = row["artifacts_json"]
        artifacts = json.loads(artifacts_raw) if artifacts_raw else []
        return ClassifiedEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            domain=row["domain"],
            techniques=[
                TechniqueAssignment(
                    technique_id=t["technique_id"],
                    technique_name=t["technique_name"] or "",
                    tactic=t["tactic"] or "",
                    confidence=t["confidence"] or 0.0,
                    reasoning=t["reasoning"] or "",
                )
                for t in techs
            ],
            asset_id=row["asset_id"],
            user_id=row["user_id"],
            location=location,
            artifacts=artifacts,
            classifier_model=row["classifier_model"] or "",
            classification_ts=datetime.fromisoformat(row["classification_ts"]),
            raw=json.loads(row["raw_json"] or "{}"),
        )

    # ---------- correlaciones ----------

    def save_correlation(self, corr: Correlation) -> bool:
        """Guarda una correlación. Devuelve True si era nueva, False si ya existía.

        Usamos INSERT OR IGNORE basado en la clave única (event_a, event_b, method).
        Esto evita duplicar correlaciones cuando se reprocesan los mismos eventos.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO correlations
                   (correlation_id, event_a_id, event_b_id, method, score,
                    delta_t_s, distance_m, metadata_json, created_ts)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(corr.correlation_id),
                    str(corr.event_a_id),
                    str(corr.event_b_id),
                    corr.method,
                    corr.score,
                    corr.delta_t_s,
                    corr.distance_m,
                    json.dumps(corr.metadata),
                    corr.created_ts.isoformat(),
                ),
            )
            return cur.rowcount > 0

    def get_correlations_for_event(
        self, event_id: str | UUID
    ) -> list[Correlation]:
        """Todas las correlaciones donde el evento aparece (como A o como B)."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM correlations
                   WHERE event_a_id = ? OR event_b_id = ?
                   ORDER BY score DESC""",
                (str(event_id), str(event_id)),
            ).fetchall()
            return [self._row_to_correlation(r) for r in rows]

    def get_correlations_for_pair(
        self, event_a_id: str | UUID, event_b_id: str | UUID,
    ) -> list[Correlation]:
        """Todas las correlaciones (de cualquier regla) que enlazan ese par."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM correlations
                   WHERE (event_a_id = ? AND event_b_id = ?)
                      OR (event_a_id = ? AND event_b_id = ?)""",
                (str(event_a_id), str(event_b_id),
                 str(event_b_id), str(event_a_id)),
            ).fetchall()
            return [self._row_to_correlation(r) for r in rows]

    def get_all_correlations(
        self, min_score: float = 0.0
    ) -> list[Correlation]:
        """Devuelve todas las correlaciones con score >= min_score."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM correlations WHERE score >= ? ORDER BY score DESC",
                (min_score,),
            ).fetchall()
            return [self._row_to_correlation(r) for r in rows]

    def _row_to_correlation(self, row: sqlite3.Row) -> Correlation:
        return Correlation(
            correlation_id=row["correlation_id"],
            event_a_id=row["event_a_id"],
            event_b_id=row["event_b_id"],
            method=row["method"],
            score=row["score"],
            delta_t_s=row["delta_t_s"],
            distance_m=row["distance_m"],
            metadata=json.loads(row["metadata_json"] or "{}"),
            created_ts=datetime.fromisoformat(row["created_ts"]),
        )

    # ---------- utilidades ----------

    def stats(self) -> dict:
        """Estadísticas rápidas del contenido. Útil para verificar inserciones."""
        with self._connect() as conn:
            n_events = conn.execute(
                "SELECT COUNT(*) AS n FROM classified_events"
            ).fetchone()["n"]
            n_cyber = conn.execute(
                "SELECT COUNT(*) AS n FROM classified_events WHERE domain='cyber'"
            ).fetchone()["n"]
            n_ew = conn.execute(
                "SELECT COUNT(*) AS n FROM classified_events WHERE domain='ew'"
            ).fetchone()["n"]
            n_techs = conn.execute(
                "SELECT COUNT(*) AS n FROM event_techniques"
            ).fetchone()["n"]
            n_corr = conn.execute(
                "SELECT COUNT(*) AS n FROM correlations"
            ).fetchone()["n"]
            return {
                "events_total": n_events,
                "events_cyber": n_cyber,
                "events_ew": n_ew,
                "techniques_total": n_techs,
                "correlations_total": n_corr,
            }