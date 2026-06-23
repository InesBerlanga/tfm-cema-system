"""Extracción de cadenas de ataque desde el grafo de correlaciones.

Modelo conceptual: los eventos son nodos, las correlaciones son aristas,
las cadenas son componentes conexos del grafo. Esto significa que NO
guardamos cadenas como entidad de primera clase en la BD — se extraen
bajo demanda a partir de las correlaciones almacenadas.

Ventajas de no materializar:
  - Re-rankear con distintos umbrales sin tocar la BD.
  - Soportar eventos que pertenecen a varias cadenas paralelas no
    interfiere con el modelo.
  - Procesar incrementalmente cada nuevo evento sin recomputar histórico.

Esta capa depende de `networkx` para extraer componentes conexos y, más
adelante, exponer el grafo a la UI.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

try:
    import networkx as nx
except ImportError as e:
    raise ImportError(
        "chains.py requiere networkx. Instala con: pip install networkx"
    ) from e

from engine import CorrelationEngine
from schemas import ClassifiedEvent, Correlation
from storage import CorrelationStore


# ============================================================================
# Chain: una cadena de ataque detectada
# ============================================================================

@dataclass
class Chain:
    """Una cadena detectada: conjunto conexo de eventos relacionados por
    una o más correlaciones (directas o transitivas).

    Los eventos se almacenan en orden cronológico (el más antiguo primero).
    Las propiedades agregadas se calculan al vuelo a partir de los eventos
    y correlaciones.
    """

    chain_id: str
    """ID determinista derivado del conjunto de eventos. La misma cadena
    (mismos event_ids) siempre obtiene el mismo chain_id, útil para cachear
    análisis aguas abajo sin tener que persistir nada."""

    events: list[ClassifiedEvent]
    """Eventos de la cadena en orden cronológico ascendente."""

    correlations: list[Correlation]
    """Todas las correlaciones internas (de cualquier regla) que enlazan
    pares de eventos pertenecientes a esta cadena. Suele haber más
    correlaciones que pares porque distintas reglas pueden disparar sobre
    el mismo par."""

    pair_strengths: dict[tuple[UUID, UUID], float]
    """Strength agregada por par, calculada con la fórmula del motor.
    Clave canónica: (event_id_a, event_id_b) ordenados por timestamp
    (el más antiguo primero)."""

    # --- Métricas básicas ---

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def pair_count(self) -> int:
        """Número de pares distintos con al menos una correlación."""
        return len(self.pair_strengths)

    @property
    def correlation_count(self) -> int:
        """Número total de correlaciones (puede ser mayor que pair_count
        porque varias reglas pueden disparar sobre el mismo par)."""
        return len(self.correlations)

    @property
    def total_strength(self) -> float:
        """Suma de las strengths agregadas de todos los pares de la cadena.
        Una cadena con muchos pares fuertes domina sobre una con un solo
        par fuerte. Es la métrica natural para rankear."""
        return sum(self.pair_strengths.values())

    @property
    def mean_strength(self) -> float:
        """Strength media por par. Comparable entre cadenas de distinta
        longitud sin penalizar a las cortas."""
        return self.total_strength / max(self.pair_count, 1)

    # --- Métricas temporales ---

    @property
    def start_ts(self) -> datetime:
        return self.events[0].timestamp

    @property
    def end_ts(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def duration_s(self) -> float:
        return (self.end_ts - self.start_ts).total_seconds()

    # --- Métricas de cobertura ---

    @property
    def domains(self) -> set[str]:
        return {ev.domain for ev in self.events}

    @property
    def is_cross_domain(self) -> bool:
        return len(self.domains) > 1

    @property
    def assets(self) -> set[str]:
        return {ev.asset_id for ev in self.events if ev.asset_id}

    @property
    def techniques(self) -> set[str]:
        return {t.technique_id for ev in self.events for t in ev.techniques}

    @property
    def tactics(self) -> set[str]:
        return {t.tactic for ev in self.events for t in ev.techniques}

    @property
    def users(self) -> set[str]:
        return {ev.user_id for ev in self.events if ev.user_id}

    # --- Métodos ---

    def summary(self) -> str:
        """Resumen breve en una línea para logging / debug."""
        return (
            f"Chain[{self.chain_id[:8]}] "
            f"events={self.event_count} pairs={self.pair_count} "
            f"total={self.total_strength:.3f} mean={self.mean_strength:.3f} "
            f"domains={sorted(self.domains)} duration={self.duration_s:.0f}s"
        )

    def to_networkx(self) -> "nx.MultiDiGraph":
        """Devuelve el grafo dirigido multi-arista de esta cadena, listo
        para visualización. Cada arista preserva toda la metadata de la
        correlación (método, score, delta_t, etc.).

        - Nodos: eventos. Atributos: timestamp, domain, asset_id,
          techniques (lista de IDs), tactics (lista de tácticas).
        - Aristas: una por correlación (multigrafo). Dirección: del evento
          más antiguo al más nuevo, siguiendo la convención del Correlation.
          Atributos: method, score, delta_t_s, distance_m, metadata.
        """
        G = nx.MultiDiGraph()
        for ev in self.events:
            G.add_node(
                ev.event_id,
                timestamp=ev.timestamp.isoformat(),
                domain=ev.domain,
                asset_id=ev.asset_id,
                user_id=ev.user_id,
                location=ev.location,
                techniques=[t.technique_id for t in ev.techniques],
                tactics=[t.tactic for t in ev.techniques],
            )
        for c in self.correlations:
            G.add_edge(
                c.event_a_id, c.event_b_id,
                key=c.method,                # multi-arista distinguida por método
                method=c.method,
                score=c.score,
                delta_t_s=c.delta_t_s,
                distance_m=c.distance_m,
                metadata=c.metadata,
            )
        return G


# ============================================================================
# ChainExtractor: la pieza que lee la BD y produce cadenas
# ============================================================================

class ChainExtractor:
    """Extrae cadenas del grafo de correlaciones almacenado en BD.

    Usa la fórmula del motor (`engine.aggregate_pair_strength`) para
    calcular la strength agregada de cada par, asegurando coherencia
    completa entre cómo se procesan eventos y cómo se rankean cadenas.
    """

    def __init__(self, storage: CorrelationStore, engine: CorrelationEngine):
        self.storage = storage
        self.engine = engine

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def extract(
        self,
        min_pair_strength: float = 0.0,
        min_events: int = 2,
    ) -> list[Chain]:
        """Extrae todas las cadenas a partir del estado actual de la BD.

        Args:
            min_pair_strength: pares con strength agregada por debajo de
                este umbral se tratan como sin conexión — se eliminan del
                grafo antes de extraer componentes. Es el "slider" del
                operador para filtrar cadenas débiles. Por defecto 0
                (todas las correlaciones cuentan).
            min_events: descarta cadenas con menos eventos que esto. Por
                defecto 2 (los eventos aislados no se devuelven aquí; usa
                `get_isolated_event_ids()` si los necesitas).

        Returns:
            Lista de Chain ordenada por `total_strength` descendente.
        """
        all_correlations = self.storage.get_all_correlations()
        if not all_correlations:
            return []

        # 1) Recopilar los eventos implicados (deduplicar antes de consultar BD)
        event_ids: set[UUID] = set()
        for c in all_correlations:
            event_ids.add(c.event_a_id)
            event_ids.add(c.event_b_id)

        events_by_id: dict[UUID, ClassifiedEvent] = {}
        for eid in event_ids:
            ev = self.storage.get_event(eid)
            if ev is not None:
                events_by_id[ev.event_id] = ev

        # 2) Agrupar correlaciones por par (canonicalizado por timestamp:
        #    el evento más antiguo va primero — coincide con la convención
        #    de Correlation.event_a_id pero hacemos la canonicalización
        #    explícita por si los timestamps coincidieran o hubiera datos
        #    inconsistentes).
        corrs_by_pair: dict[tuple[UUID, UUID], list[Correlation]] = {}
        for c in all_correlations:
            ev_a = events_by_id.get(c.event_a_id)
            ev_b = events_by_id.get(c.event_b_id)
            if ev_a is None or ev_b is None:
                continue
            key = self._canonical_pair_key(ev_a, ev_b)
            corrs_by_pair.setdefault(key, []).append(c)

        # 3) Calcular la strength agregada de cada par usando el motor
        pair_strengths: dict[tuple[UUID, UUID], float] = {}
        for (id_a, id_b), corrs in corrs_by_pair.items():
            ev_a = events_by_id[id_a]
            ev_b = events_by_id[id_b]
            pair_strengths[(id_a, id_b)] = self.engine.aggregate_pair_strength(
                corrs, ev_a, ev_b
            )

        # 4) Construir el grafo simple (no dirigido) para componentes conexos.
        #    Filtramos aristas por umbral de strength agregada.
        G = nx.Graph()
        # Añadimos todos los nodos primero para asegurar que eventos cuyos
        # únicos pares cayeron por debajo del umbral aparezcan como aislados.
        for eid in event_ids:
            G.add_node(eid)
        for (id_a, id_b), strength in pair_strengths.items():
            if strength >= min_pair_strength:
                G.add_edge(id_a, id_b, weight=strength)

        # 5) Extraer componentes conexos y construir Chain por cada uno
        chains: list[Chain] = []
        for component in nx.connected_components(G):
            if len(component) < min_events:
                continue

            chain_events = sorted(
                (events_by_id[eid] for eid in component if eid in events_by_id),
                key=lambda e: e.timestamp,
            )
            if len(chain_events) < min_events:
                continue

            # Recopilar correlaciones internas y strengths de la cadena.
            # Solo las que sobrepasaron el filtro (consistencia con el grafo).
            chain_correlations: list[Correlation] = []
            chain_pair_strengths: dict[tuple[UUID, UUID], float] = {}
            for pair_key, corrs in corrs_by_pair.items():
                id_a, id_b = pair_key
                if id_a in component and id_b in component:
                    s = pair_strengths.get(pair_key, 0.0)
                    if s >= min_pair_strength:
                        chain_correlations.extend(corrs)
                        chain_pair_strengths[pair_key] = s

            chains.append(Chain(
                chain_id=_make_chain_id(component),
                events=chain_events,
                correlations=chain_correlations,
                pair_strengths=chain_pair_strengths,
            ))

        # 6) Ranking por total_strength descendente
        chains.sort(key=lambda c: c.total_strength, reverse=True)
        return chains

    # ------------------------------------------------------------------
    # Consultas auxiliares
    # ------------------------------------------------------------------

    def get_chain_for_event(
        self,
        event_id: UUID | str,
        min_pair_strength: float = 0.0,
        min_events: int = 2,
    ) -> Optional[Chain]:
        """Devuelve la cadena que contiene el evento dado, o None si está
        aislado o no aparece en ninguna cadena que pase los filtros.
        """
        target = str(event_id)
        for chain in self.extract(
            min_pair_strength=min_pair_strength,
            min_events=min_events,
        ):
            if any(str(ev.event_id) == target for ev in chain.events):
                return chain
        return None

    def get_isolated_event_ids(
        self,
        min_pair_strength: float = 0.0,
    ) -> set[UUID]:
        """Devuelve los IDs de eventos que NO entran en ninguna cadena
        (todas sus correlaciones cayeron por debajo del umbral, o no
        tienen correlaciones).
        """
        all_correlations = self.storage.get_all_correlations()
        # Eventos que aparecen en correlaciones que sobrepasan el umbral.
        # Si min_pair_strength es 0 esto basta con tener una correlación.
        events_with_strong_links: set[UUID] = set()
        if all_correlations:
            event_ids: set[UUID] = set()
            for c in all_correlations:
                event_ids.add(c.event_a_id)
                event_ids.add(c.event_b_id)
            events_by_id = {
                eid: self.storage.get_event(eid) for eid in event_ids
            }
            corrs_by_pair: dict[tuple[UUID, UUID], list[Correlation]] = {}
            for c in all_correlations:
                ev_a = events_by_id.get(c.event_a_id)
                ev_b = events_by_id.get(c.event_b_id)
                if ev_a is None or ev_b is None:
                    continue
                key = self._canonical_pair_key(ev_a, ev_b)
                corrs_by_pair.setdefault(key, []).append(c)
            for pair_key, corrs in corrs_by_pair.items():
                ev_a = events_by_id[pair_key[0]]
                ev_b = events_by_id[pair_key[1]]
                if ev_a is None or ev_b is None:
                    continue
                s = self.engine.aggregate_pair_strength(corrs, ev_a, ev_b)
                if s >= min_pair_strength:
                    events_with_strong_links.add(pair_key[0])
                    events_with_strong_links.add(pair_key[1])

        # Todo evento de la BD que no esté en events_with_strong_links está aislado.
        # Necesitamos saber qué eventos hay en BD: usamos stats() y get_events_in_window
        # con una ventana enorme. Más limpio sería un método list_all_events en
        # storage, pero esto vale para PoC.
        # Para no asumir bound temporal, dejamos al usuario obtener eventos.
        # Aquí devolvemos solo eventos correlacionados que cayeron por filtro.
        all_event_ids: set[UUID] = set()
        for c in all_correlations:
            all_event_ids.add(c.event_a_id)
            all_event_ids.add(c.event_b_id)
        return all_event_ids - events_with_strong_links

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical_pair_key(
        ev_a: ClassifiedEvent, ev_b: ClassifiedEvent
    ) -> tuple[UUID, UUID]:
        """Clave canónica para un par: el más antiguo primero. Empate
        temporal se rompe por ordenación lexicográfica del UUID.
        """
        if ev_a.timestamp < ev_b.timestamp:
            return (ev_a.event_id, ev_b.event_id)
        if ev_a.timestamp > ev_b.timestamp:
            return (ev_b.event_id, ev_a.event_id)
        # Empate: comparamos UUIDs como strings
        if str(ev_a.event_id) < str(ev_b.event_id):
            return (ev_a.event_id, ev_b.event_id)
        return (ev_b.event_id, ev_a.event_id)


def _make_chain_id(event_ids: set[UUID]) -> str:
    """Genera un chain_id determinista a partir del conjunto de eventos.

    Misma cadena (mismo conjunto de event_ids) → mismo chain_id, sin
    persistencia. Devuelve los primeros 16 chars del SHA-1 del concat.
    """
    sorted_ids = sorted(str(e) for e in event_ids)
    return hashlib.sha1("|".join(sorted_ids).encode()).hexdigest()[:16]
