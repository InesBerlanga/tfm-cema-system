"""Pipeline end-to-end del sistema CEMA: clasificación + correlación.

Carga la configuración desde un JSON y construye todo el grafo de objetos:
  - cliente(s) LLM (uno por dominio; reutilizados si la configuración coincide)
  - clasificadores cyber y EW
  - almacén SQLite
  - motor de correlación con las 5 reglas

Uso típico:

    pipeline = Pipeline.from_config("config.json")

    # con eventos crudos (pasan por el LLM):
    classified, new_corrs = pipeline.process_cyber(raw_cyber_event)
    classified, new_corrs = pipeline.process_ew(raw_ew_event)

    # con eventos ya clasificados (skip LLM, útil en tests):
    new_corrs = pipeline.process_classified(classified_event)

El config.json centraliza todos los parámetros tuneables. Las claves que
empiezan por '_' (como '_description') se ignoran al iterar — se permiten
como comentarios embebidos para legibilidad.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from chains import ChainExtractor
from countermeasures import CountermeasureRecommender
from cyber_classifier import CyberClassifier
from engine import CorrelationEngine
from ew_classifier import EwClassifier
from llm_client import get_llm
from predictor import ChainPredictor
from rules import (
    AssetConvergenceRule,
    CorrelationRule,
    CrossDomainMappingRule,
    GeographicProximityRule,
    KillChainRule,
    SharedArtifactRule,
)
from schemas import ClassifiedEvent, Correlation, RawCyberEvent, RawEwEvent
from storage import CorrelationStore


# ============================================================================
# Registro de constructores de reglas
# ============================================================================
# Mapea el nombre canónico de la regla (el mismo que en config["rules"] y en
# config["rule_weights"]) al callable que la construye. Recibe el dict de
# paths absolutos resueltos y los params específicos de esa regla.
#
# Para añadir una regla nueva:
#   1. Defínela en rules.py
#   2. Regístrala aquí
#   3. Añade su entrada en config["rules"] y config["rule_weights"]
# ============================================================================

RuleConstructor = Callable[[dict[str, Path], dict[str, Any]], CorrelationRule]

RULE_CONSTRUCTORS: dict[str, RuleConstructor] = {
    "kill_chain": lambda paths, p: KillChainRule(
        tactics_order_path=paths["tactics_order"],
        window_seconds=p["window_seconds"],
    ),
    "cross_domain": lambda paths, p: CrossDomainMappingRule(
        mapping_path=paths["ew_mitre_mapping"],
        window_seconds=p["window_seconds"],
    ),
    "asset_convergence": lambda paths, p: AssetConvergenceRule(
        window_seconds=p["window_seconds"],
    ),
    "geo_proximity": lambda paths, p: GeographicProximityRule(
        max_distance_m=p["max_distance_m"],
        tau_d_m=p["tau_d_m"],
        window_seconds=p["window_seconds"],
    ),
    "shared_artifact": lambda paths, p: SharedArtifactRule(
        window_seconds=p["window_seconds"],
    ),
}


# ============================================================================
# Utilidades de config
# ============================================================================

def _strip_meta(d: dict) -> dict:
    """Devuelve una copia del dict sin las claves que empiezan por '_'.

    Esas claves se usan como pseudo-comentarios en el JSON (que no admite
    comentarios reales) y no deben aparecer al iterar parámetros.
    """
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ============================================================================
# Pipeline
# ============================================================================

class Pipeline:
    """Orquestador del flujo completo: clasificación → motor de correlación
    → extracción de cadenas → predicción → contramedidas.

    Atributos públicos (útiles desde fuera si necesitas acceso directo):
        config:           dict con el config completo
        storage:          CorrelationStore
        engine:           CorrelationEngine
        cyber_clf:        CyberClassifier
        ew_clf:           EwClassifier
        chain_extractor:  ChainExtractor (componentes conexas del grafo)
        predictor:        ChainPredictor (predicción LLM de continuaciones)
        recommender:      CountermeasureRecommender (defensas para cadenas)
    """

    def __init__(self, config: dict[str, Any], base_path: Path):
        self.config = config
        self._base = Path(base_path).resolve()

        # ----- Resolver paths del config (relativos al directorio del config) -----
        raw_paths = _strip_meta(config["paths"])
        self._paths: dict[str, Path] = {
            k: self._resolve(v) for k, v in raw_paths.items()
        }

        # ----- Clientes LLM (uno por uso; reuso si configs idénticos) -----
        llm_cfg = _strip_meta(config["llm"])
        cyber_llm_cfg = llm_cfg["cyber"]
        ew_llm_cfg = llm_cfg["ew"]
        predictor_llm_cfg = llm_cfg.get("predictor", cyber_llm_cfg)

        cyber_llm = get_llm(
            model=cyber_llm_cfg["model"],
            temperature=cyber_llm_cfg.get("temperature", 0.1),
            max_tokens=cyber_llm_cfg.get("max_tokens", 512),
        )
        if ew_llm_cfg == cyber_llm_cfg:
            ew_llm = cyber_llm  # mismo cliente, ahorra una conexión
        else:
            ew_llm = get_llm(
                model=ew_llm_cfg["model"],
                temperature=ew_llm_cfg.get("temperature", 0.1),
                max_tokens=ew_llm_cfg.get("max_tokens", 512),
            )
        # Predictor: reusa cyber o ew si la config coincide, si no crea uno propio
        if predictor_llm_cfg == cyber_llm_cfg:
            predictor_llm = cyber_llm
        elif predictor_llm_cfg == ew_llm_cfg:
            predictor_llm = ew_llm
        else:
            predictor_llm = get_llm(
                model=predictor_llm_cfg["model"],
                temperature=predictor_llm_cfg.get("temperature", 0.3),
                max_tokens=predictor_llm_cfg.get("max_tokens", 1024),
            )

        # ----- Clasificadores -----
        self.cyber_clf = CyberClassifier(cyber_llm, self._paths["mitre_techniques"])
        self.ew_clf = EwClassifier(ew_llm, self._paths["ew_techniques"])

        # ----- Storage -----
        self.storage = CorrelationStore(self._paths["db"])

        # ----- Reglas: construidas a partir del config -----
        rules_cfg = _strip_meta(config["rules"])
        rules: list[CorrelationRule] = []
        for method, params in rules_cfg.items():
            constructor = RULE_CONSTRUCTORS.get(method)
            if constructor is None:
                raise ValueError(
                    f"Regla desconocida en config: '{method}'. "
                    f"Constructores disponibles: {sorted(RULE_CONSTRUCTORS)}."
                )
            rules.append(constructor(self._paths, params))

        # ----- Pesos: ignorando los pseudo-comentarios -----
        rule_weights = {
            k: float(v)
            for k, v in _strip_meta(config["rule_weights"]).items()
        }

        # ----- Motor -----
        self.engine = CorrelationEngine(
            storage=self.storage,
            rules=rules,
            rule_weights=rule_weights,
            global_tau_t=float(config["correlation"]["global_tau_t"]),
        )

        # ----- Capas analíticas: extracción de cadenas + predictor + contramedidas -----
        self.chain_extractor = ChainExtractor(
            storage=self.storage,
            engine=self.engine,
        )
        self.predictor = ChainPredictor(
            llm=predictor_llm,
            mitre_techniques_path=self._paths["mitre_techniques"],
            ew_techniques_path=self._paths["ew_techniques"],
            tactics_order_path=self._paths["tactics_order"],
        )
        self.recommender = CountermeasureRecommender(
            cyber_path=self._paths["mitre_countermeasures"],
            ew_path=self._paths["ew_countermeasures"],
        )

    @classmethod
    def from_config(cls, config_path: str | Path) -> "Pipeline":
        """Construye un Pipeline cargando el config desde un fichero JSON."""
        config_path = Path(config_path).resolve()
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)
        return cls(config, base_path=config_path.parent)

    def _resolve(self, p: str) -> Path:
        """Resuelve un path del config relativo al directorio del fichero
        config. Si el path es absoluto se devuelve tal cual.
        """
        path = Path(p)
        if path.is_absolute():
            return path
        return (self._base / path).resolve()

    # ------------------------------------------------------------------
    # Procesado de eventos
    # ------------------------------------------------------------------

    def process_cyber(
        self, raw_event: RawCyberEvent
    ) -> tuple[ClassifiedEvent, list[Correlation]]:
        """Clasifica un evento ciber con el LLM y lo pasa al motor.

        Devuelve (ClassifiedEvent, lista de correlaciones nuevas).
        """
        classified = self.cyber_clf.classify(raw_event)
        new_correlations = self.engine.process(classified)
        return classified, new_correlations

    def process_ew(
        self, raw_event: RawEwEvent
    ) -> tuple[ClassifiedEvent, list[Correlation]]:
        """Clasifica un evento EW con el LLM y lo pasa al motor.

        Devuelve (ClassifiedEvent, lista de correlaciones nuevas).
        """
        classified = self.ew_clf.classify(raw_event)
        new_correlations = self.engine.process(classified)
        return classified, new_correlations

    def process_classified(
        self, classified: ClassifiedEvent
    ) -> list[Correlation]:
        """Pasa al motor un evento que YA está clasificado (skip LLM).

        Útil para tests sintéticos o para reprocesar la BD sin re-clasificar.
        """
        return self.engine.process(classified)