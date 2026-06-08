"""Clase base de los clasificadores ciber y EW.

La lógica de clasificación es idéntica en ambos dominios:
  1. Cargar el catálogo de técnicas (JSON).
  2. Construir un prompt con rol + catálogo + esquema JSON de salida.
  3. Invocar el LLM con el evento.
  4. Parsear la respuesta (JSON).
  5. Filtrar IDs alucinados (no presentes en el catálogo).
  6. Devolver un ClassifiedEvent.

Solo el rol, el formato del catálogo y el formato del evento cambian entre
dominios — esas tres cosas son los métodos abstractos.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

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
      "confidence": <number between 0.0 and 1.0>,
      "reasoning": "<one short sentence justifying the assignment>"
    }
  ]
}

Strict rules:
- If no catalog technique clearly applies, return {"techniques": []}.
- Do not invent IDs. Only use IDs that appear literally in the catalog.
- Do not include explanations outside the JSON and do not wrap it in ```.
- Be conservative: a wrong classification is worse than no classification."""


def _extract_json(text: str) -> str:
    """Extrae el bloque JSON de la respuesta del LLM.

    Tolera respuestas envueltas en ```json ... ``` o con texto antes/después.
    """
    # Caso 1: code fence
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        return fence.group(1)
    # Caso 2: primer {...} balanceado a ojo
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text  # se intentará parsear tal cual


def _clean_description(text: str, max_len: int = 200) -> str:
    """Limpia y trunca una descripción para meterla en el prompt.

    - Reemplaza enlaces markdown [texto](url) por solo el texto.
    - Quita backticks de código.
    - Colapsa whitespace repetido (saltos de línea, espacios múltiples).
    - Trunca en frontera de palabra (no parte palabras a la mitad).
    """
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    text = text.replace('`', '')
    text = ' '.join(text.split())
    if len(text) > max_len:
        text = text[:max_len].rsplit(' ', 1)[0] + '…'
    return text


class BaseTechniqueClassifier(ABC):
    """Esqueleto común. Implementa los hooks abstractos en las subclases."""

    #: "cyber" o "ew"; se usa para etiquetar el ClassifiedEvent
    domain: str

    def __init__(self, llm: ChatOpenAI, catalog_path: Path | str):
        self.llm = llm
        self.catalog: list[dict[str, Any]] = self._load_catalog(Path(catalog_path))
        self.valid_ids: set[str] = {t["id"] for t in self.catalog}

    # ---------- Hooks que cada dominio debe definir ----------

    @abstractmethod
    def _system_role(self) -> str:
        """Descripción del rol del analista (ciber o EW)."""

    @abstractmethod
    def _format_catalog(self) -> str:
        """Renderiza el catálogo en texto para el system prompt."""

    @abstractmethod
    def _format_event(self, event: Any) -> str:
        """Renderiza el evento de entrada en texto para el user prompt."""

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
        """Clasifica un evento. En caso de fallo de parseo, reintenta una vez."""
        messages = self._build_messages(event)
        last_error: Exception | None = None

        raw = ""
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

        # Filtra IDs alucinados
        valid = [t for t in parsed.techniques if t.technique_id in self.valid_ids]
        dropped = len(parsed.techniques) - len(valid)
        if dropped:
            print(
                f"[INFO] {dropped} técnica(s) descartada(s) por ID inválido "
                f"en evento {getattr(event, 'event_id', '?')}"
            )

        return ClassifiedEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            domain=self.domain,
            techniques=valid,
            classifier_model=self.llm.model_name,
            raw=event.model_dump(mode="json"),
        )
