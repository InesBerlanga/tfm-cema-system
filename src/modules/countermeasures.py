"""Recomendador de contramedidas para cadenas de ataque detectadas.

Dada una `Chain` (y opcionalmente una `ChainPrediction` del módulo predictor),
este módulo consulta dos catálogos de contramedidas (uno ciber, uno EW) y
devuelve una lista priorizada de defensas aplicables.

Cada contramedida puede cubrir varias técnicas de la cadena; cuanto más amplia
es esa cobertura, más alta la prioridad — reflejando eficiencia defensiva.
Las contramedidas que actúan sobre técnicas YA observadas (reactivas) pesan
más que las que actúan sobre técnicas predichas (preventivas), porque las
hipotéticas pueden no llegar a ocurrir.

Formatos esperados de los ficheros de conocimiento:

  Cyber (mitre_techniques_countermeasures.json) — formato MITRE/D3FEND:
    [
      {
        "attack_technique_id": "T1001",
        "attack_technique_name": "Data Obfuscation",
        "attack_parent": null,
        "attack_tactics": ["command-and-control"],
        "recommended_countermeasures": [
          {"id": "...", "name": "...", "top_level": "...", "tactics": ["detect"]}
        ]
      }
    ]

  EW (ew_techniques_countermeasures.json) — formato propio:
    [
      {
        "id": "TEW01",
        "name": "Electromagnetic Reconnaissance",
        "role": "adversary-technique",
        "tactics": ["detect"],
        "description": "...",
        "countermeasures": [
          {"id": "TEW13", "name": "Electromagnetic Masking"}
        ]
      }
    ]
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from chains import Chain


# ============================================================================
# Estructuras de datos
# ============================================================================

Domain = Literal["cyber", "ew"]
Source = Literal["observed", "predicted"]


@dataclass(frozen=True)
class Countermeasure:
    """Una contramedida atómica (defensa).

    Frozen=True para que sea hashable y podamos usarla como clave en agrupados.
    El top_level solo está poblado para contramedidas ciber (es la categoría
    D3FEND padre). En EW lo dejamos a None.
    """
    id: str
    name: str
    domain: Domain
    tactics: tuple[str, ...] = field(default_factory=tuple)
    top_level: Optional[str] = None


@dataclass
class TechniqueCovered:
    """Una técnica de la cadena cubierta por una contramedida.

    El `source` distingue si la técnica ya fue observada o si solo es una
    predicción. Esto afecta a la priorización: las observadas pesan más
    que las predichas.
    """
    technique_id: str
    technique_name: str
    domain: Domain
    source: Source


@dataclass
class CountermeasureMatch:
    """Una contramedida aplicable + el detalle de qué técnicas cubre.

    `priority` es la métrica de ranking. Se calcula como
        Σ (peso por fuente) sobre las técnicas cubiertas,
    donde el peso por defecto es 1.0 para observed y 0.5 para predicted.
    """
    countermeasure: Countermeasure
    covers: list[TechniqueCovered]
    priority: float

    @property
    def technique_count(self) -> int:
        return len(self.covers)

    @property
    def is_preemptive_only(self) -> bool:
        """True si esta contramedida solo cubre técnicas PREDICHAS (no observadas).

        Útil para distinguir defensas "preventivas" en la UI: no las tienes que
        activar para mitigar algo ya observado, son una previsión.
        """
        return all(tc.source == "predicted" for tc in self.covers)

    @property
    def covers_observed(self) -> list[TechniqueCovered]:
        return [tc for tc in self.covers if tc.source == "observed"]

    @property
    def covers_predicted(self) -> list[TechniqueCovered]:
        return [tc for tc in self.covers if tc.source == "predicted"]


@dataclass
class CountermeasureRecommendation:
    """Resultado del recomendador para una cadena concreta."""
    chain_id: str
    matches: list[CountermeasureMatch]
    techniques_with_no_match: list[TechniqueCovered]

    @property
    def total_matches(self) -> int:
        return len(self.matches)

    def by_domain(self) -> dict[Domain, list[CountermeasureMatch]]:
        result: dict[Domain, list[CountermeasureMatch]] = {"cyber": [], "ew": []}
        for m in self.matches:
            result[m.countermeasure.domain].append(m)
        return result

    @property
    def reactive_matches(self) -> list[CountermeasureMatch]:
        """Contramedidas que cubren al menos una técnica observada."""
        return [m for m in self.matches if not m.is_preemptive_only]

    @property
    def preemptive_matches(self) -> list[CountermeasureMatch]:
        """Contramedidas que solo cubren técnicas predichas."""
        return [m for m in self.matches if m.is_preemptive_only]


# ============================================================================
# Recomendador
# ============================================================================

class CountermeasureRecommender:
    """Recomienda contramedidas para cadenas de ataque.

    Carga los dos catálogos de mapeo técnica→contramedidas y mantiene índices
    inversos para look-up O(1) durante la recomendación.
    """

    def __init__(
        self,
        cyber_path: Path | str,
        ew_path: Path | str,
    ):
        self._cyber_index: dict[str, list[Countermeasure]] = self._load_cyber_index(
            Path(cyber_path)
        )
        self._ew_index: dict[str, list[Countermeasure]] = self._load_ew_index(
            Path(ew_path)
        )

    # ---------- Carga e indexado ----------

    @staticmethod
    def _load_cyber_index(path: Path) -> dict[str, list[Countermeasure]]:
        """Lee mitre_techniques_countermeasures.json y construye
        attack_technique_id -> [Countermeasure(...), ...].
        """
        if not path.exists():
            print(f"[WARN] Cyber countermeasures file not found at {path}. "
                  f"No cyber recommendations will be produced.")
            return {}
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        index: dict[str, list[Countermeasure]] = {}
        for entry in data:
            tech_id = entry.get("attack_technique_id")
            if not tech_id:
                continue
            counters = []
            for c in entry.get("recommended_countermeasures", []):
                if not c.get("id"):
                    continue
                counters.append(Countermeasure(
                    id=c["id"],
                    name=c.get("name", c["id"]),
                    domain="cyber",
                    tactics=tuple(c.get("tactics", [])),
                    top_level=c.get("top_level"),
                ))
            if counters:
                index[tech_id] = counters
        return index

    @staticmethod
    def _load_ew_index(path: Path) -> dict[str, list[Countermeasure]]:
        """Lee ew_techniques_countermeasures.json y construye
        ew_technique_id -> [Countermeasure(...), ...].
        """
        if not path.exists():
            print(f"[WARN] EW countermeasures file not found at {path}. "
                  f"No EW recommendations will be produced.")
            return {}
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        index: dict[str, list[Countermeasure]] = {}
        for entry in data:
            tech_id = entry.get("id")
            if not tech_id:
                continue
            # Solo consideramos entradas que tienen 'countermeasures' definido y
            # representan técnicas ofensivas (role 'adversary-technique' o sin role).
            # Las técnicas defensivas (TEW13 etc.) aparecen como contramedidas en
            # otras entradas, no como entradas que tengan countermeasures propias.
            counters_data = entry.get("countermeasures", [])
            if not counters_data:
                continue
            counters = []
            for c in counters_data:
                if not c.get("id"):
                    continue
                counters.append(Countermeasure(
                    id=c["id"],
                    name=c.get("name", c["id"]),
                    domain="ew",
                    tactics=tuple(c.get("tactics", [])),
                    top_level=None,
                ))
            if counters:
                index[tech_id] = counters
        return index

    # ---------- API principal ----------

    def recommend(
        self,
        chain: Chain,
        predictions: Optional[list] = None,  # list[TechniquePrediction]
        observed_weight: float = 1.0,
        prediction_weight: float = 0.5,
    ) -> CountermeasureRecommendation:
        """Genera recomendaciones para una cadena concreta.

        Args:
            chain: la cadena detectada.
            predictions: opcional, lista de TechniquePrediction del módulo
                predictor. Si se incluye, también se recomiendan contramedidas
                para esas técnicas (preventivas).
            observed_weight: peso de cada técnica observada en el cálculo de
                prioridad. Default 1.0.
            prediction_weight: peso de cada técnica predicha. Default 0.5
                (la mitad de las observadas, porque las predichas pueden no
                llegar a ocurrir).

        Returns:
            CountermeasureRecommendation con `matches` ordenado por prioridad
            descendente.
        """
        # 1) Recopilar técnicas observadas de la cadena (deduplicadas por id+dominio)
        observed: dict[tuple[str, Domain], TechniqueCovered] = {}
        for ev in chain.events:
            for t in ev.techniques:
                key = (t.technique_id, ev.domain)
                if key not in observed:
                    observed[key] = TechniqueCovered(
                        technique_id=t.technique_id,
                        technique_name=t.technique_name,
                        domain=ev.domain,
                        source="observed",
                    )

        # 2) Recopilar técnicas predichas (si vienen)
        predicted: dict[tuple[str, Domain], TechniqueCovered] = {}
        if predictions:
            for p in predictions:
                key = (p.technique_id, p.domain)
                # Si ya está observada, prevalece como observed (no doble cuenta)
                if key in observed:
                    continue
                if key not in predicted:
                    predicted[key] = TechniqueCovered(
                        technique_id=p.technique_id,
                        technique_name=p.technique_name,
                        domain=p.domain,
                        source="predicted",
                    )

        all_techniques: list[TechniqueCovered] = list(observed.values()) + list(predicted.values())

        # 3) Look-up de contramedidas por técnica y agregación por contramedida
        cm_to_covers: dict[Countermeasure, list[TechniqueCovered]] = {}
        techniques_with_no_match: list[TechniqueCovered] = []

        for tc in all_techniques:
            index = self._cyber_index if tc.domain == "cyber" else self._ew_index
            counters = index.get(tc.technique_id)
            if not counters:
                techniques_with_no_match.append(tc)
                continue
            for cm in counters:
                cm_to_covers.setdefault(cm, []).append(tc)

        # 4) Construir matches con prioridad
        matches: list[CountermeasureMatch] = []
        for cm, covers in cm_to_covers.items():
            priority = sum(
                observed_weight if tc.source == "observed" else prediction_weight
                for tc in covers
            )
            matches.append(CountermeasureMatch(
                countermeasure=cm,
                covers=covers,
                priority=priority,
            ))

        # 5) Ranking por prioridad descendente; secundario por nombre para estabilidad
        matches.sort(
            key=lambda m: (-m.priority, m.countermeasure.name),
        )

        return CountermeasureRecommendation(
            chain_id=chain.chain_id,
            matches=matches,
            techniques_with_no_match=techniques_with_no_match,
        )
