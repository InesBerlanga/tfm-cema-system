"""Clase base de los clasificadores ciber y EW.

Pipeline:
  1. Cargar el catálogo de técnicas (JSON).
  2. Construir un prompt con rol + catálogo + esquema JSON de salida que
     incluye táctica única por técnica.
  3. Invocar el LLM.
  4. Parsear la respuesta (JSON).
  5. Filtrar:
       - IDs no presentes en el catálogo (alucinaciones del LLM).
       - Tácticas no listadas para la técnica concreta en el catálogo
         (cuando el LLM elige una táctica fuera de las admitidas).
  6. Extraer del raw los campos que necesitan las reglas de correlación:
     asset_id, user_id, location, artifacts. Lógica específica de dominio.
  7. Devolver ClassifiedEvent.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError

from schemas import ClassifiedEvent, TechniqueAssignment


class _LLMOutput(BaseModel):
    """Schema interno de salida que pedimos al LLM."""
    techniques: list[TechniqueAssignment] = Field(default_factory=list)


JSON_INSTRUCTIONS = """Return ONLY a JSON object with this structure:
{
  "techniques": [
    {
      "technique_id": "<exact ID from the catalog>",
      "technique_name": "<name exactly as it appears in the catalog>",
      "tactic": "<ONE single tactic from those listed for this technique>",
      "confidence": <number between 0.0 and 1.0>,
      "reasoning": "<one short sentence justifying the assignment>"
    }
  ]
}

Strict rules:
- For "tactic": pick EXACTLY ONE tactic from the list shown after "tactics:"
  on the catalog line for that technique. Choose the tactic that best fits
  the context of THIS event. Do NOT invent tactic names.
- If no catalog technique clearly applies, return {"techniques": []}.
- Do not invent IDs. Only use IDs that appear literally in the catalog.
- Do not include explanations outside the JSON and do not wrap it in ```.
- Be conservative: a wrong classification is worse than no classification."""


def _extract_json(text: str) -> str:
    """Extrae el bloque JSON de la respuesta del LLM."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def _clean_description(text: str, max_len: int = 80) -> str:
    """Limpia y trunca una descripción para meterla en el prompt."""
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    text = text.replace('`', '')
    text = ' '.join(text.split())
    if len(text) > max_len:
        text = text[:max_len].rsplit(' ', 1)[0] + '…'
    return text


class BaseTechniqueClassifier(ABC):
    """Esqueleto común. Las subclases implementan los hooks abstractos."""

    domain: str  # "cyber" o "ew"

    def __init__(self, llm: ChatOpenAI, catalog_path: Path | str):
        self.llm = llm
        self.catalog: list[dict[str, Any]] = self._load_catalog(Path(catalog_path))
        # Validación de IDs (anti-alucinación)
        self.valid_ids: set[str] = {t["id"] for t in self.catalog}
        # Validación de tácticas por técnica: ID -> {tácticas admitidas}
        self.tactics_by_id: dict[str, set[str]] = {
            t["id"]: set(t.get("tactics", [])) for t in self.catalog
        }

    # ---------- Hooks abstractos: contenido del prompt ----------

    @abstractmethod
    def _system_role(self) -> str:
        """Descripción del rol del analista (ciber o EW)."""

    @abstractmethod
    def _format_catalog(self) -> str:
        """Renderiza el catálogo en texto para el system prompt."""

    @abstractmethod
    def _format_event(self, event: Any) -> str:
        """Renderiza el evento de entrada en texto para el user prompt."""

    # ---------- Hooks abstractos: extracción de campos del raw ----------
    # Estos campos NO los emite el LLM. Los extraemos del evento crudo en
    # cada clasificador porque su ubicación depende del formato (ECS para
    # ciber, sensor/signal/detection para EW).

    @abstractmethod
    def _extract_asset_id(self, event: Any) -> Optional[str]:
        """Devuelve el ID del activo afectado leído del evento raw.

        - Cyber (ECS): event.host.name o event.host.id.
        - EW: event.detection.affected_system.
        """

    @abstractmethod
    def _extract_user_id(self, event: Any) -> Optional[str]:
        """Devuelve la identidad de usuario asociada al evento.

        - Cyber (ECS): event.user.name si existe.
        - EW: típicamente None (los sensores RF no tienen concepto de usuario).
        """

    @abstractmethod
    def _extract_location(self, event: Any) -> Optional[tuple[float, float]]:
        """Devuelve (lat, lon) si el evento lleva geolocalización.

        - Cyber: típicamente None (ECS no suele llevar coordenadas).
        - EW: (sensor.lat, sensor.lon) si ambos están presentes.
        """

    @abstractmethod
    def _extract_artifacts(self, event: Any) -> list[str]:
        """Devuelve la lista de IoCs observables en el evento.

        Cada artefacto se devuelve en formato 'tipo:valor'. Tipos admitidos:
        - 'ip:<addr>'     IP de destino
        - 'hash:<sha256>' hash de fichero
        - 'domain:<fqdn>' nombre DNS consultado

        - Cyber (ECS): saca dst IP, file.hash.*, dns.question.name del raw.
        - EW: típicamente lista vacía.
        """

    # ---------- Lógica común ----------

    def _load_catalog(self, path: Path) -> list[dict[str, Any]]:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"El catálogo {path} debe ser una lista de objetos.")
        return data

    def _build_messages(self, event: Any) -> list[Any]:
        system_content = (
            f"{self._system_role()}\n\n"
            f"Available techniques catalog:\n{self._format_catalog()}\n\n"
            f"{JSON_INSTRUCTIONS}"
        )
        return [
            SystemMessage(content=system_content),
            HumanMessage(content=self._format_event(event)),
        ]

    def classify(self, event: Any, retries: int = 1) -> ClassifiedEvent:
        """Clasifica un evento. En fallo de parseo reintenta una vez."""
        messages = self._build_messages(event)
        last_error: Exception | None = None
        raw = ""
        parsed: _LLMOutput = _LLMOutput(techniques=[])

        for attempt in range(retries + 1):
            try:
                response = self.llm.invoke(messages)
                raw = response.content if isinstance(response.content, str) \
                    else str(response.content)
                if not raw.strip():
                    raise ValueError("LLM returned an empty response")
                json_text = _extract_json(raw)
                parsed = _LLMOutput.model_validate_json(json_text)
                break
            except (ValidationError, json.JSONDecodeError, ValueError) as e:
                last_error = e
                if attempt < retries:
                    messages = self._build_messages(event) + [
                        HumanMessage(content=(
                            "Your previous response was not valid JSON. "
                            "Return ONLY the JSON object described, nothing else."
                        ))
                    ]
                else:
                    raw_preview = repr(raw[:300]) if raw else "<empty>"
                    print(
                        f"[WARN] Failed to parse LLM output for event "
                        f"{getattr(event, 'event_id', '?')}: {e} | raw={raw_preview}"
                    )
                    parsed = _LLMOutput(techniques=[])

        # Validación: ID en catálogo + táctica admitida para esa técnica
        valid: list[TechniqueAssignment] = []
        dropped_id = 0
        dropped_tactic = 0
        for t in parsed.techniques:
            if t.technique_id not in self.valid_ids:
                dropped_id += 1
                continue
            allowed_tactics = self.tactics_by_id.get(t.technique_id, set())
            if t.tactic not in allowed_tactics:
                dropped_tactic += 1
                continue
            valid.append(t)

        ev_id = getattr(event, 'event_id', '?')
        if dropped_id:
            print(f"[INFO] {dropped_id} técnica(s) descartada(s) por ID inválido (evento {ev_id})")
        if dropped_tactic:
            print(f"[INFO] {dropped_tactic} técnica(s) descartada(s) por táctica no admitida (evento {ev_id})")

        return ClassifiedEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            domain=self.domain,
            techniques=valid,
            asset_id=self._extract_asset_id(event),
            user_id=self._extract_user_id(event),
            location=self._extract_location(event),
            artifacts=self._extract_artifacts(event),
            classifier_model=self.llm.model_name,
            raw=event.model_dump(mode="json", by_alias=True),
        )