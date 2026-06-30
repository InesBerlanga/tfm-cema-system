"""Predicción LLM de la continuación de una cadena de ataque.

Dada una cadena parcial (`Chain`), el predictor pide a un LLM que proponga
las técnicas más plausibles que el adversario podría usar a continuación,
en cualquier dominio (cyber o EW).

Esto es donde el LLM aporta valor frente a lógica determinista: razonar
sobre kill chains incompletas y proponer continuaciones coherentes con el
patrón observado, posiblemente cross-dominio. La salida es estructurada
(IDs validados contra los catálogos, tácticas comprobadas) para que el
módulo de contramedidas o la UI puedan usarla sin parsear texto libre.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError

from chains import Chain
from classifier_base import _clean_description, _extract_json


# ============================================================================
# Schemas de salida
# ============================================================================

class TechniquePrediction(BaseModel):
    """Predicción de una técnica que podría aparecer a continuación."""
    technique_id: str = Field(description="ID exacto del catálogo (ej. T1486, TEW06.2)")
    technique_name: str
    tactic: str
    domain: Literal["cyber", "ew"]
    probability: float = Field(ge=0.0, le=1.0, description="Plausibilidad subjetiva")
    reasoning: str = Field(description="Justificación específica de esta predicción")


class ChainPrediction(BaseModel):
    """Predicción global para una cadena observada."""
    chain_id: str
    overall_reasoning: str = Field(
        description="Explicación de alto nivel de hacia dónde va la cadena"
    )
    predictions: list[TechniquePrediction] = Field(
        default_factory=list,
        description="Próximas técnicas plausibles, ordenadas por probabilidad descendente",
    )


# ============================================================================
# Prompts
# ============================================================================

PREDICTOR_ROLE = """You are a CEMA (Cyber-Electromagnetic Activities) analyst
specializing in adversary playbook analysis. Your task is to predict which
techniques an adversary might use NEXT, given an observed chain of attack
events that may span the cyber and electromagnetic warfare domains.

Doctrinal context: in coordinated CEMA operations, cyber and EW phases often
interleave. An adversary may use EW reconnaissance to enable cyber initial
access, follow cyber persistence with EW jamming for kinetic effect, or
combine cyber deception with EW deception (meaconing) to disrupt operations.

Your predictions should reflect this reality — propose continuations in
EITHER domain, picking whichever techniques are most plausible given the
observed pattern."""


JSON_INSTRUCTIONS = """Return ONLY a JSON object with this structure:
{
  "overall_reasoning": "<one sentence about where the chain is heading>",
  "predictions": [
    {
      "technique_id": "<exact ID from the catalogs>",
      "technique_name": "<name exactly as in the catalog>",
      "tactic": "<ONE tactic from those listed for this technique>",
      "domain": "cyber" or "ew",
      "probability": <number between 0.0 and 1.0>,
      "reasoning": "<one short sentence justifying this prediction>"
    }
  ]
}

Strict rules:
- Predict between 3 and N techniques (N given in the user request). Order by
  decreasing probability.
- For "technique_id" and "technique_name": copy exactly from the catalog.
- For "tactic": pick ONE tactic listed for this technique in the catalog.
- For "domain": cyber for MITRE techniques (T*), ew for EW techniques (TEW*).
- Be CONSERVATIVE: probability reflects how likely this is to actually appear.
  Wrong predictions cost credibility. Spread probabilities (do not assign 0.9
  to all).
- Do not invent IDs or names. Do not include explanations outside the JSON.
- Do not wrap the JSON in ```."""


# ============================================================================
# Predictor
# ============================================================================

class _LLMOutput(BaseModel):
    """Schema interno para parsear la respuesta del LLM antes de validar
    contra catálogos."""
    overall_reasoning: str = ""
    predictions: list[TechniquePrediction] = Field(default_factory=list)


class ChainPredictor:
    """Predice técnicas que podrían continuar una cadena observada.

    Carga los dos catálogos (MITRE + EW) y los tiers de tácticas. Cada
    llamada `predict(chain)` construye un prompt con esos catálogos + la
    cadena formateada y pide al LLM que devuelva 3-5 candidatos.

    Las predicciones se validan estrictamente:
      - technique_id debe existir en alguno de los catálogos.
      - tactic debe estar admitida para esa técnica.
      - domain debe coincidir con el catálogo (cyber/ew) al que pertenece
        el technique_id (corregimos si el LLM se confunde).

    Las predicciones que no pasen las validaciones se descartan.
    """

    def __init__(
        self,
        llm: ChatOpenAI,
        mitre_techniques_path: Path | str,
        ew_techniques_path: Path | str,
        tactics_order_path: Path | str,
        description_max_chars: int = 60,
    ):
        self.llm = llm
        self._desc_max = description_max_chars

        # Cargar catálogos
        with Path(mitre_techniques_path).open("r", encoding="utf-8") as f:
            self.cyber_catalog: list[dict[str, Any]] = json.load(f)
        with Path(ew_techniques_path).open("r", encoding="utf-8") as f:
            self.ew_catalog: list[dict[str, Any]] = json.load(f)

        # Índices para validación O(1)
        self._cyber_ids: set[str] = {t["id"] for t in self.cyber_catalog}
        self._ew_ids: set[str] = {t["id"] for t in self.ew_catalog}
        self._tactics_by_id: dict[str, set[str]] = {}
        for cat in (self.cyber_catalog, self.ew_catalog):
            for t in cat:
                self._tactics_by_id[t["id"]] = set(t.get("tactics", []))

        # Cargar orden de tácticas (tiers) para describir al LLM las fases
        with Path(tactics_order_path).open("r", encoding="utf-8") as f:
            order_data = json.load(f)
        self._tiers: list[dict[str, Any]] = order_data["tiers"]
        # Mapa tactic -> nombre del tier (para anotar la cadena observada)
        self._tactic_to_tier: dict[str, str] = {}
        for tier in self._tiers:
            for tactic in tier.get("tactics", []):
                # Primera ocurrencia: si una táctica vive en varios tiers,
                # describimos el más temprano (mismo criterio "benefit of doubt"
                # que usa KillChainRule).
                self._tactic_to_tier.setdefault(tactic, tier["name"])

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def predict(
        self,
        chain: Chain,
        max_predictions: int = 5,
        retries: int = 1,
    ) -> ChainPrediction:
        """Pide al LLM hasta `max_predictions` próximas técnicas para la cadena.

        Args:
            chain: la cadena observada (debe tener al menos 1 evento con técnicas).
            max_predictions: tope superior. El LLM puede devolver menos.
            retries: reintentos si el JSON sale malformado.

        Returns:
            ChainPrediction con las predicciones validadas, ordenadas por
            probability descendente.
        """
        # Cadena vacía o sin técnicas: devolver vacío
        if not chain.events or chain.event_count == 0:
            return ChainPrediction(chain_id=chain.chain_id, overall_reasoning="", predictions=[])
        if not any(ev.techniques for ev in chain.events):
            return ChainPrediction(
                chain_id=chain.chain_id,
                overall_reasoning="No hay técnicas clasificadas en la cadena.",
                predictions=[],
            )

        messages = self._build_messages(chain, max_predictions)
        last_error: Exception | None = None
        raw_text = ""
        parsed: _LLMOutput = _LLMOutput()

        for attempt in range(retries + 1):
            try:
                response = self.llm.invoke(messages)
                raw_text = (
                    response.content if isinstance(response.content, str)
                    else str(response.content)
                )
                if not raw_text.strip():
                    raise ValueError("LLM returned an empty response")
                parsed = _LLMOutput.model_validate_json(_extract_json(raw_text))
                break
            except (ValidationError, json.JSONDecodeError, ValueError) as e:
                last_error = e
                if attempt < retries:
                    messages = self._build_messages(chain, max_predictions) + [
                        HumanMessage(content=(
                            "Your previous response was not valid JSON. "
                            "Return ONLY the JSON object described, nothing else."
                        ))
                    ]
                else:
                    preview = repr(raw_text[:300]) if raw_text else "<empty>"
                    print(
                        f"[WARN] ChainPredictor: fallo de parseo en cadena "
                        f"{chain.chain_id}: {e} | raw={preview}"
                    )

        # Validar y limpiar predicciones
        valid_predictions: list[TechniquePrediction] = []
        dropped_id = 0
        dropped_tactic = 0
        dropped_domain = 0
        for p in parsed.predictions:
            # 1) ID válido
            inferred_domain: Optional[str] = None
            if p.technique_id in self._cyber_ids:
                inferred_domain = "cyber"
            elif p.technique_id in self._ew_ids:
                inferred_domain = "ew"
            else:
                dropped_id += 1
                continue
            # 2) Táctica admitida para esa técnica
            allowed = self._tactics_by_id.get(p.technique_id, set())
            if p.tactic not in allowed:
                dropped_tactic += 1
                continue
            # 3) Domain inferido del catálogo prevalece sobre lo que diga el LLM
            if p.domain != inferred_domain:
                dropped_domain += 1
                p = p.model_copy(update={"domain": inferred_domain})  # corregimos
            valid_predictions.append(p)

        if dropped_id:
            print(f"[INFO] {dropped_id} predicción(es) descartada(s) por ID inválido (cadena {chain.chain_id})")
        if dropped_tactic:
            print(f"[INFO] {dropped_tactic} predicción(es) descartada(s) por táctica no admitida")
        if dropped_domain:
            print(f"[INFO] {dropped_domain} predicción(es) con dominio corregido según catálogo")

        # Ordenar por probabilidad descendente y truncar
        valid_predictions.sort(key=lambda p: p.probability, reverse=True)
        valid_predictions = valid_predictions[:max_predictions]

        return ChainPrediction(
            chain_id=chain.chain_id,
            overall_reasoning=parsed.overall_reasoning,
            predictions=valid_predictions,
        )

    # ------------------------------------------------------------------
    # Renderizado del prompt
    # ------------------------------------------------------------------

    def _build_messages(self, chain: Chain, max_predictions: int) -> list[Any]:
        system_content = (
            f"{PREDICTOR_ROLE}\n\n"
            f"Cyber techniques catalog (MITRE ATT&CK — names are self-explanatory):\n"
            f"{self._format_mitre_catalog()}\n\n"
            f"EW techniques catalog (custom taxonomy with descriptions):\n"
            f"{self._format_ew_catalog()}\n\n"
            f"Kill chain phases (events typically progress from earlier to later phases):\n"
            f"{self._format_tiers()}\n\n"
            f"{JSON_INSTRUCTIONS}"
        )
        user_content = self._format_chain(chain) + (
            f"\n\nPredict up to {max_predictions} most plausible next techniques."
        )
        return [SystemMessage(content=system_content), HumanMessage(content=user_content)]

    def _format_mitre_catalog(self) -> str:
        """MITRE: ID + nombre + tácticas (sin descripción).

        Razón: el LLM tiene amplio conocimiento previo de MITRE ATT&CK desde
        su entrenamiento, las descripciones añadirían tokens sin información
        relevante. El catálogo sirve sobre todo como "lista de IDs válidos"
        contra la que validar la respuesta.
        """
        lines = []
        for t in self.cyber_catalog:
            tactics = ", ".join(t.get("tactics", [])) or "?"
            lines.append(f"- {t['id']} | {t['name']} | tactics: {tactics}")
        return "\n".join(lines)

    def _format_ew_catalog(self) -> str:
        """EW: ID + nombre + tácticas + descripción truncada.

        Razón: las técnicas EW son taxonomía propia del proyecto, el LLM no
        las conoce, por lo que la descripción aporta contexto crítico para
        que las prediga apropiadamente.
        """
        lines = []
        for t in self.ew_catalog:
            tactics = ", ".join(t.get("tactics", [])) or "?"
            desc = _clean_description(t.get("description") or "", max_len=self._desc_max)
            lines.append(f"- {t['id']} | {t['name']} | tactics: {tactics} | {desc}")
        return "\n".join(lines)

    def _format_tiers(self) -> str:
        """Resumen compacto del orden de tiers para que el LLM vea las fases."""
        lines = []
        for i, tier in enumerate(self._tiers):
            tactics = ", ".join(tier.get("tactics", []))
            lines.append(f"  Tier {i} ({tier['name']}): {tactics}")
        return "\n".join(lines)

    def _format_chain(self, chain: Chain) -> str:
        """Renderiza la cadena observada en orden cronológico."""
        lines = ["Observed chain (chronological):"]
        for i, ev in enumerate(chain.events, start=1):
            ts = ev.timestamp.strftime("%H:%M:%S")
            tech_parts = []
            for t in ev.techniques:
                tier = self._tactic_to_tier.get(t.tactic, "?")
                tech_parts.append(
                    f"{t.technique_id} {t.technique_name} ({t.tactic}, tier={tier})"
                )
            tech_str = "; ".join(tech_parts) if tech_parts else "(no techniques)"
            asset = ev.asset_id or "?"
            lines.append(f"  [{i}] {ev.domain} @ {ts} | asset={asset} | {tech_str}")

        # Métricas resumen útiles para el LLM
        lines.append("")
        lines.append(f"Chain metrics:")
        lines.append(f"  - Duration: {chain.duration_s:.0f}s")
        lines.append(f"  - Cross-domain: {chain.is_cross_domain}")
        lines.append(f"  - Domains observed: {sorted(chain.domains)}")
        lines.append(f"  - Assets touched: {sorted(chain.assets)}")
        lines.append(f"  - Tactics covered: {sorted(chain.tactics)}")
        tiers_covered = sorted({
            self._tactic_to_tier.get(t, "?") for t in chain.tactics
        })
        lines.append(f"  - Tiers covered: {tiers_covered}")
        return "\n".join(lines)
