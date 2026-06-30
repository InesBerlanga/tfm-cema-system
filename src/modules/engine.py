"""Motor de correlación.

Orquesta el flujo:

  1. Recibe un ClassifiedEvent nuevo.
  2. Lo persiste en storage.
  3. Consulta los eventos candidatos dentro de la ventana máxima.
  4. Para cada candidato:
     - Determina el tipo de par (frozenset de dominios).
     - Dispatch por applicable_pairs (Patrón B): solo evalúa las reglas que
       declaran cubrir ese tipo de par.
     - Cada regla devuelve una Correlation con score = EVIDENCIA PURA.
     - El motor guarda esa correlación.
  5. Opcionalmente calcula la fuerza agregada del par:

        strength(A,B) = conf(A) · conf(B) · exp(−ΔT/τ_t_global)
                        · Σ (w_rule · score_rule)

     donde la suma corre sobre todas las correlaciones (de distintas reglas)
     que enlazan ese par. Los `w_rule` son los pesos asignados a cada regla
     en la configuración del motor; idealmente suman 1 para que `strength`
     quede acotada en [0, 1].
"""

from __future__ import annotations

import math
from typing import Optional

from schemas import ClassifiedEvent, Correlation
from rules import CorrelationRule
from storage import CorrelationStore


class CorrelationEngine:
    def __init__(
        self,
        storage: CorrelationStore,
        rules: list[CorrelationRule],
        rule_weights: dict[str, float],
        global_tau_t: float = 300.0,
    ):
        """Inicializa el motor con un conjunto de reglas y sus pesos.

        Parámetros:
          storage         -- CorrelationStore para persistir eventos y correlaciones.
          rules           -- lista de instancias de CorrelationRule.
          rule_weights    -- {method -> peso}. Idealmente Σ pesos = 1.
                             Se valida que todas las reglas configuradas tengan
                             peso. Reglas sin peso no podrán contribuir a la
                             fuerza agregada.
          global_tau_t    -- constante de decaimiento temporal en segundos,
                             aplicada globalmente al agregar (no en las reglas).
        """
        self.storage = storage
        self.rules = rules
        self.rule_weights = dict(rule_weights)
        self.global_tau_t = float(global_tau_t)

        # Validar que toda regla tiene peso configurado (defensa frente a errores).
        missing = [r.method for r in rules if r.method not in self.rule_weights]
        if missing:
            raise ValueError(
                f"rule_weights no incluye pesos para las reglas: {missing}. "
                "Añádelos al diccionario rule_weights."
            )
        # Aviso (no error) si los pesos no suman 1 — el modelo asume esa propiedad
        # para que `strength` quede acotada en [0, 1], pero matemáticamente no
        # se rompe nada si no lo hacen.
        total_w = sum(self.rule_weights.values())
        if not math.isclose(total_w, 1.0, abs_tol=1e-3):
            print(
                f"[WARN] rule_weights suma {total_w:.3f} (esperado ~1.0). "
                "La fuerza agregada del par podrá exceder 1.0."
            )

        # Calcular la ventana máxima (la más laxa) para consultar candidatos.
        self._max_window = max(r.window_seconds for r in rules)

        # Precomputar la suma de pesos de reglas aplicables a cada tipo de par.
        # Esto permite normalizar la fuerza agregada al rango [0, 1] de forma
        # uniforme entre cyber-cyber, ew-ew y cross-dominio, eliminando el
        # sesgo de "cuántas reglas pueden aplicar a este par".
        # Tipos canónicos: {cyber}, {ew}, {cyber, ew}.
        self._weight_sum_by_pair_type: dict[frozenset[str], float] = {}
        for pair_type in (
            frozenset({"cyber"}),
            frozenset({"ew"}),
            frozenset({"cyber", "ew"}),
        ):
            total = 0.0
            for rule in self.rules:
                if rule.applicable_pairs == "any" or pair_type in rule.applicable_pairs:
                    total += self.rule_weights.get(rule.method, 0.0)
            self._weight_sum_by_pair_type[pair_type] = total

        # Sanidad: ningún tipo de par debería tener Σ w aplicables = 0
        # (eso significaría que para ese tipo de par no contribuye NINGUNA
        # regla, y la fuerza agregada sería siempre 0).
        empty_types = [
            t for t, s in self._weight_sum_by_pair_type.items() if s <= 0
        ]
        if empty_types:
            print(
                f"[WARN] Tipos de par sin reglas aplicables con peso > 0: "
                f"{[set(t) for t in empty_types]}. La fuerza agregada para "
                f"esos pares será siempre 0."
            )

    # ------------------------------------------------------------------
    # Procesado de eventos entrantes
    # ------------------------------------------------------------------

    def process(self, new_event: ClassifiedEvent) -> list[Correlation]:
        """Procesa un nuevo evento. Persiste, busca candidatos en ventana,
        evalúa todas las reglas aplicables, guarda las correlaciones nuevas.

        Devuelve la lista de correlaciones nuevas (no las que ya existían
        en BD por idempotencia INSERT OR IGNORE).
        """
        self.storage.save_event(new_event)

        candidates = self.storage.get_events_in_window(
            new_event.timestamp,
            self._max_window,
        )
        new_correlations: list[Correlation] = []

        for candidate in candidates:
            if candidate.event_id == new_event.event_id:
                continue

            # Convención: event_a es el más antiguo.
            if candidate.timestamp <= new_event.timestamp:
                ev_a, ev_b = candidate, new_event
            else:
                ev_a, ev_b = new_event, candidate

            pair_type = frozenset({ev_a.domain, ev_b.domain})

            for rule in self.rules:
                # Dispatch por applicable_pairs (Patrón B)
                if rule.applicable_pairs != "any":
                    if pair_type not in rule.applicable_pairs:
                        continue
                corr = rule.evaluate(ev_a, ev_b)
                if corr is None:
                    continue
                was_new = self.storage.save_correlation(corr)
                if was_new:
                    new_correlations.append(corr)

        return new_correlations

    # ------------------------------------------------------------------
    # Fuerza agregada del par
    # ------------------------------------------------------------------

    def aggregate_pair_strength(
        self,
        correlations: list[Correlation],
        ev_a: ClassifiedEvent,
        ev_b: ClassifiedEvent,
    ) -> float:
        """Calcula la fuerza agregada del par usando la fórmula global,
        NORMALIZADA por el peso total de reglas aplicables al tipo de par:

            strength = conf(A) · conf(B) · exp(−ΔT/τ_t_global)
                                         · ( Σ w_i · score_i )
                                           ───────────────────
                                            Σ aplicables w_i

        El denominador (precomputado en __init__) es la suma de pesos de
        TODAS las reglas que aplican a ese tipo de par, hayan o no
        disparado. Eso normaliza la strength a [0, 1] uniformemente entre
        cyber-cyber, ew-ew y cross-dominio: una correlación con evidencia
        plena llega a 1.0 sea cual sea el tipo de par.

        Si la lista de correlaciones está vacía, devuelve 0.0.
        """
        if not correlations:
            return 0.0
        delta_t = abs((ev_b.timestamp - ev_a.timestamp).total_seconds())
        temporal_decay = math.exp(-delta_t / self.global_tau_t)
        conf_a = max((t.confidence for t in ev_a.techniques), default=0.0)
        conf_b = max((t.confidence for t in ev_b.techniques), default=0.0)

        weighted_sum = sum(
            c.score * self.rule_weights.get(c.method, 0.0)
            for c in correlations
        )

        # Normalizar por las reglas aplicables al tipo de par concreto.
        pair_type = frozenset({ev_a.domain, ev_b.domain})
        norm = self._weight_sum_by_pair_type.get(pair_type, 0.0)
        if norm > 0:
            weighted_sum = weighted_sum / norm

        return conf_a * conf_b * temporal_decay * weighted_sum

    def get_pair_strength(
        self,
        ev_a: ClassifiedEvent,
        ev_b: ClassifiedEvent,
    ) -> float:
        """Conveniencia: consulta las correlaciones del par en BD y calcula
        la fuerza agregada en una sola llamada.
        """
        corrs = self.storage.get_correlations_for_pair(
            ev_a.event_id, ev_b.event_id
        )
        return self.aggregate_pair_strength(corrs, ev_a, ev_b)
