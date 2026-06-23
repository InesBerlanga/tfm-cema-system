"""Reglas de correlación entre pares de eventos clasificados.

Cada regla emite una `Correlation` cuyo campo `score` es EVIDENCIA PURA en
[0, 1]: representa solo lo que esa regla específica observa para el par
concreto, sin incluir decaimiento temporal ni confianza del clasificador
(esos factores los aplica el motor globalmente al agregar las correlaciones
del par).

Patrón B (dispatch declarativo): cada regla declara `applicable_pairs` con
el conjunto de combinaciones de dominios para las que aplica. El motor lee
ese atributo y omite la regla en pares no aplicables.

  applicable_pairs valores admitidos:
    "any"                                 -> cualquier combinación
    [frozenset({"cyber"})]                -> solo cyber-cyber
    [frozenset({"ew"})]                   -> solo ew-ew
    [frozenset({"cyber", "ew"})]          -> solo cross-dominio
"""

from __future__ import annotations

import json
import math
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union

from schemas import ClassifiedEvent, Correlation


# ============================================================================
# Utilidades
# ============================================================================

def haversine_distance_m(
    loc_a: tuple[float, float],
    loc_b: tuple[float, float],
) -> float:
    """Distancia haversine en metros entre dos coordenadas (lat, lon).

    Usa el radio medio de la Tierra (6 371 008 m). Precisión > 99.5% para
    distancias urbanas/regionales, suficiente para correlación táctica.
    """
    lat_a, lon_a = map(math.radians, loc_a)
    lat_b, lon_b = map(math.radians, loc_b)
    dlat = lat_b - lat_a
    dlon = lon_b - lon_a
    a = math.sin(dlat / 2) ** 2 + math.cos(lat_a) * math.cos(lat_b) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    return 6_371_008.0 * c


# ============================================================================
# Clase base
# ============================================================================

PairsSpec = Union[str, list[frozenset[str]]]  # "any" o lista de frozensets


class CorrelationRule(ABC):
    """Esqueleto de una regla de correlación pairwise.

    Subclases deben declarar:
      - applicable_pairs: PairsSpec (atributo de clase)
      - method: nombre canónico que se almacena en Correlation.method
      - window_seconds: float; eventos fuera de esta ventana no se evalúan
    """

    applicable_pairs: PairsSpec
    method: str
    window_seconds: float

    @abstractmethod
    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        """Devuelve una Correlation con score = evidencia pura, o None.

        Pre-condición: event_a.timestamp <= event_b.timestamp.
        Pre-condición: el motor ya ha verificado applicable_pairs.
        La regla puede asumir esas dos cosas.
        """

    # ---------- helpers para subclases ----------

    def _check_window(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[float]:
        """Devuelve delta_t (seg) si ambos eventos están en la ventana de la regla.
        En caso contrario devuelve None. Asume event_a anterior a event_b.
        """
        delta_t = (event_b.timestamp - event_a.timestamp).total_seconds()
        if delta_t < 0 or delta_t > self.window_seconds:
            return None
        return delta_t


# ============================================================================
# R1 — Kill chain plausibility (unificada, cualquier combinación de dominios)
# ============================================================================

class KillChainRule(CorrelationRule):
    """R1. Detecta avance plausible del kill chain entre dos eventos.

    Carga un fichero `tactics_order.json` con tiers ordenados. Las tácticas
    dentro de un tier son paralelas (distancia 0). Algunas tácticas (como
    'deceive') aparecen en varios tiers y se manejan con lista de posiciones.

    Score puro: 1.0 si existe al menos un par de técnicas (ta, tb) cuyas
    tácticas admitan una transición no decreciente entre tiers. La distancia
    de tier queda en metadata pero NO penaliza el score (los chains EW-only
    que saltan el tier 2 no se ven perjudicados).
    """

    applicable_pairs: PairsSpec = "any"
    method: str = "kill_chain"

    def __init__(self, tactics_order_path: Union[str, Path], window_seconds: float = 1800.0):
        self.window_seconds = float(window_seconds)
        with Path(tactics_order_path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        tiers = data["tiers"]
        # Tactic -> [posiciones de tier].  Una táctica puede repetirse en varios
        # tiers (por ejemplo 'deceive' en intrusion y effect).
        self._tactic_positions: dict[str, list[int]] = {}
        for tier_idx, tier in enumerate(tiers):
            for tactic in tier.get("tactics", []):
                self._tactic_positions.setdefault(tactic, []).append(tier_idx)
        self._tier_names: list[str] = [t.get("name", f"tier-{i}") for i, t in enumerate(tiers)]

    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        delta_t = self._check_window(event_a, event_b)
        if delta_t is None:
            return None
        if not event_a.techniques or not event_b.techniques:
            return None

        # Busca el mejor par (ta, tb) con tier(ta) <= tier(tb) y menor distancia.
        best = None
        best_dist: Optional[int] = None
        for ta in event_a.techniques:
            positions_a = self._tactic_positions.get(ta.tactic, [])
            if not positions_a:
                continue
            for tb in event_b.techniques:
                positions_b = self._tactic_positions.get(tb.tactic, [])
                if not positions_b:
                    continue
                # Si la táctica vive en varios tiers, escoge la combinación
                # más favorable (menor distancia siendo no negativa).
                valid = [(pa, pb) for pa in positions_a for pb in positions_b if pa <= pb]
                if not valid:
                    continue
                pa, pb = min(valid, key=lambda x: x[1] - x[0])
                dist = pb - pa
                if best_dist is None or dist < best_dist:
                    best = (ta, tb, pa, pb)
                    best_dist = dist

        if best is None:
            return None

        ta, tb, pa, pb = best
        return Correlation(
            event_a_id=event_a.event_id,
            event_b_id=event_b.event_id,
            method=self.method,
            score=1.0,  # evidencia pura: binaria
            delta_t_s=round(delta_t, 2),
            metadata={
                "from_technique": ta.technique_id,
                "from_tactic": ta.tactic,
                "from_tier": self._tier_names[pa],
                "to_technique": tb.technique_id,
                "to_tactic": tb.tactic,
                "to_tier": self._tier_names[pb],
                "tier_distance": best_dist,
                "cross_domain": event_a.domain != event_b.domain,
            },
        )


# ============================================================================
# R2 — Cross-domain doctrinal mapping (EW <-> MITRE)
# ============================================================================

class CrossDomainMappingRule(CorrelationRule):
    """R2. Vincula eventos ciber y EW según la matriz doctrinal experta.

    Carga `ew_mitre_mapping.json` con la estructura:
        { "TEW_id": { "MITRE_id": mapping_weight, ... }, ... }

    Score puro: mapping_weight del mejor par técnica_ew × técnica_mitre que
    aparezca en la matriz. Con pesos binarios (1.0 en toda la matriz) el
    score es siempre 1.0 cuando la regla dispara.
    """

    applicable_pairs: PairsSpec = [frozenset({"cyber", "ew"})]
    method: str = "cross_domain"

    def __init__(
        self,
        mapping_path: Union[str, Path],
        window_seconds: float = 3600.0,
    ):
        self.window_seconds = float(window_seconds)
        with Path(mapping_path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Limpiamos claves auxiliares que empiezan con guion bajo (notas).
        self.mapping: dict[str, dict[str, float]] = {
            k: v for k, v in data.items()
            if not k.startswith("_") and isinstance(v, dict)
        }

    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        delta_t = self._check_window(event_a, event_b)
        if delta_t is None:
            return None
        if not event_a.techniques or not event_b.techniques:
            return None

        # Identificar quién es EW y quién es ciber (el motor garantiza que
        # el par es cross-dominio, pero el orden a/b depende del tiempo).
        if event_a.domain == "ew" and event_b.domain == "cyber":
            ew_ev, cyber_ev = event_a, event_b
        elif event_a.domain == "cyber" and event_b.domain == "ew":
            ew_ev, cyber_ev = event_b, event_a
        else:
            return None  # No debería ocurrir: el motor ya filtró por pairs.

        # Buscar el par (técnica EW, técnica MITRE) con mapeo de mayor peso.
        best = None
        best_w: float = 0.0
        for t_ew in ew_ev.techniques:
            cyber_mappings = self.mapping.get(t_ew.technique_id)
            if not cyber_mappings:
                continue
            for t_cyber in cyber_ev.techniques:
                w = cyber_mappings.get(t_cyber.technique_id)
                if w is None:
                    continue
                if w > best_w:
                    best_w = w
                    best = (t_ew, t_cyber, w)

        if best is None:
            return None

        t_ew, t_cyber, w = best
        return Correlation(
            event_a_id=event_a.event_id,
            event_b_id=event_b.event_id,
            method=self.method,
            score=float(w),  # evidencia pura: peso del mapeo
            delta_t_s=round(delta_t, 2),
            metadata={
                "ew_technique": t_ew.technique_id,
                "ew_tactic": t_ew.tactic,
                "mitre_technique": t_cyber.technique_id,
                "mitre_tactic": t_cyber.tactic,
                "mapping_weight": float(w),
            },
        )


# ============================================================================
# R3 — Asset convergence
# ============================================================================

class AssetConvergenceRule(CorrelationRule):
    """R3. Eventos que tocan el mismo activo.

    Aplica a cualquier combinación de dominios — es la regla que "barata"
    detecta convergencias cross-dominio cuando dos sistemas comparten el
    mismo identificador de activo.

    Score puro: 1.0 si los assets coinciden, no dispara en caso contrario.
    """

    applicable_pairs: PairsSpec = "any"
    method: str = "asset_convergence"

    def __init__(self, window_seconds: float = 600.0):
        self.window_seconds = float(window_seconds)

    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        if not event_a.asset_id or not event_b.asset_id:
            return None
        if event_a.asset_id != event_b.asset_id:
            return None
        if not event_a.techniques or not event_b.techniques:
            return None
        delta_t = self._check_window(event_a, event_b)
        if delta_t is None:
            return None
        return Correlation(
            event_a_id=event_a.event_id,
            event_b_id=event_b.event_id,
            method=self.method,
            score=1.0,  # evidencia pura: binaria
            delta_t_s=round(delta_t, 2),
            metadata={
                "asset_id": event_a.asset_id,
                "domain_a": event_a.domain,
                "domain_b": event_b.domain,
                "cross_domain": event_a.domain != event_b.domain,
            },
        )


# ============================================================================
# R5 — Geographic proximity (eventos EW-EW)
# ============================================================================

class GeographicProximityRule(CorrelationRule):
    """R5. Correlaciona dos eventos EW cuyos sensores están físicamente próximos.

    Score puro: exp(−distancia_m / tau_d_m). Gradiente intrínseco a la regla
    (no es un factor común que el motor pueda extraer). Eventos en el mismo
    punto → score 1.0; a tau_d_m metros → ~0.37; a 2·tau_d_m → ~0.14.

    Filtro: la distancia ha de ser ≤ max_distance_m para evitar correlaciones
    de larga distancia que carecen de sentido operativo.
    """

    applicable_pairs: PairsSpec = [frozenset({"ew"})]
    method: str = "geo_proximity"

    def __init__(
        self,
        max_distance_m: float = 5000.0,
        tau_d_m: float = 1000.0,
        window_seconds: float = 600.0,
    ):
        self.max_distance_m = float(max_distance_m)
        self.tau_d_m = float(tau_d_m)
        self.window_seconds = float(window_seconds)

    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        if event_a.location is None or event_b.location is None:
            return None
        if not event_a.techniques or not event_b.techniques:
            return None
        delta_t = self._check_window(event_a, event_b)
        if delta_t is None:
            return None
        distance_m = haversine_distance_m(event_a.location, event_b.location)
        if distance_m > self.max_distance_m:
            return None
        score = math.exp(-distance_m / self.tau_d_m)
        return Correlation(
            event_a_id=event_a.event_id,
            event_b_id=event_b.event_id,
            method=self.method,
            score=score,
            delta_t_s=round(delta_t, 2),
            distance_m=round(distance_m, 1),
            metadata={
                "location_a": list(event_a.location),
                "location_b": list(event_b.location),
                "tau_d_m": self.tau_d_m,
            },
        )


# ============================================================================
# R6 — Shared artifact (IoC compartido entre dos eventos ciber)
# ============================================================================

class SharedArtifactRule(CorrelationRule):
    """R6. Eventos ciber que comparten al menos un artefacto observable.

    Los artefactos vienen del extractor del CyberClassifier en formato
    'tipo:valor', donde tipo ∈ {hash, ip, domain, user}. La regla calcula
    el peso intrínseco del mejor artefacto compartido y lo devuelve:

        hash    -> 1.0   (casi imposible que sean independientes)
        ip      -> 0.8   (puede haber reúso de infra, también CDN compartido)
        domain  -> 0.7   (similar a IP)
        user    -> 0.6   (señal de movimiento lateral, ver nota abajo)

    Sobre el artefacto 'user': estrictamente no es un IoC del adversario sino
    una identidad legítima del entorno. Compartirlo solo es relevante cuando
    los eventos están en activos DIFERENTES (señal de movimiento lateral del
    actor que controla la cuenta). En el mismo activo no aporta sobre R3, así
    que aquí lo filtramos.

    El stoplist de usuarios genéricos (admin/root/SYSTEM/etc.) se aplica
    aguas arriba, en CyberClassifier._extract_artifacts: usuarios genéricos
    no llegan a la lista de artefactos.

    Score puro: el peso del artefacto compartido más fuerte que pase los
    filtros. No incluye decaimiento temporal — los artefactos persisten en
    el tiempo, por eso la ventana de R6 es la más laxa de todas (default 2 h).
    """

    applicable_pairs: PairsSpec = [frozenset({"cyber"})]
    method: str = "shared_artifact"

    ARTIFACT_STRENGTHS: dict[str, float] = {
        "hash": 1.0,
        "ip": 0.8,
        "domain": 0.7,
        "user": 0.6,
    }
    DEFAULT_STRENGTH: float = 0.5

    def __init__(self, window_seconds: float = 7200.0):
        self.window_seconds = float(window_seconds)

    def evaluate(
        self, event_a: ClassifiedEvent, event_b: ClassifiedEvent
    ) -> Optional[Correlation]:
        if not event_a.artifacts or not event_b.artifacts:
            return None
        shared = set(event_a.artifacts) & set(event_b.artifacts)
        if not shared:
            return None
        if not event_a.techniques or not event_b.techniques:
            return None
        delta_t = self._check_window(event_a, event_b)
        if delta_t is None:
            return None

        # Caso especial 'user:...': solo cuenta si los assets difieren
        # (señal de movimiento lateral). Si los assets coinciden o falta uno,
        # R3 ya cubre la correlación; añadir 'user' aquí no aportaría nada.
        same_asset = (
            event_a.asset_id is not None
            and event_b.asset_id is not None
            and event_a.asset_id == event_b.asset_id
        )

        best_strength: float = 0.0
        best_artifact: Optional[str] = None
        qualifying: list[str] = []
        for artifact in shared:
            kind = artifact.split(":", 1)[0] if ":" in artifact else ""
            if kind == "user" and same_asset:
                # Mismo asset → 'user' no aporta evidencia adicional.
                continue
            qualifying.append(artifact)
            strength = self.ARTIFACT_STRENGTHS.get(kind, self.DEFAULT_STRENGTH)
            if strength > best_strength:
                best_strength = strength
                best_artifact = artifact

        if not qualifying:
            return None

        return Correlation(
            event_a_id=event_a.event_id,
            event_b_id=event_b.event_id,
            method=self.method,
            score=best_strength,  # evidencia pura: peso categórico
            delta_t_s=round(delta_t, 2),
            metadata={
                "shared_artifacts": sorted(qualifying),
                "best_artifact": best_artifact,
                "best_strength": best_strength,
            },
        )
