"""Esquemas de datos del sistema.

Define los contratos entre los módulos:
- RawCyberEvent / RawEwEvent: lo que entra al clasificador.
- TechniqueAssignment: técnica identificada + confianza + justificación.
- ClassifiedEvent: lo que sale del clasificador, listo para correlación.
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


# ---------- Eventos de entrada ----------

class RawCyberEvent(BaseModel):
    """Evento ciber tal como llega de una fuente (SIEM, IDS, EDR...)."""
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source: str = Field(description="Sensor o herramienta que generó el evento")
    raw_text: str = Field(description="Texto/log del evento")
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    asset_id: Optional[str] = Field(
        default=None, description="Identificador del activo afectado (si se conoce)"
    )
    severity: Optional[int] = Field(default=None, ge=1, le=5)


class RawEwEvent(BaseModel):
    """Evento EW tal como llega de un sensor radioeléctrico (SDR, analizador...)."""
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source: str = Field(description="Sensor RF que generó el evento")
    raw_description: str = Field(
        description="Descripción textual del fenómeno detectado"
    )
    freq_center_mhz: Optional[float] = None
    bandwidth_khz: Optional[float] = None
    power_dbm: Optional[float] = None
    doa_deg: Optional[float] = Field(
        default=None, ge=0, le=360, description="Direction of Arrival en grados"
    )
    location: Optional[tuple[float, float]] = Field(
        default=None, description="(lat, lon) si se conoce"
    )
    asset_id: Optional[str] = None


# ---------- Salida del clasificador ----------

class TechniqueAssignment(BaseModel):
    """Una técnica identificada en un evento."""
    technique_id: str = Field(description="ID del catálogo (ej. T1059, EW-EA-001)")
    technique_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(
        default="", description="Breve justificación del LLM"
    )


class ClassifiedEvent(BaseModel):
    """Evento normalizado y clasificado, listo para entrar al correlador."""
    event_id: UUID
    timestamp: datetime
    domain: Literal["cyber", "ew"]
    techniques: list[TechniqueAssignment]
    classifier_model: str = Field(description="Modelo LLM usado")
    classification_ts: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    raw: dict = Field(
        default_factory=dict,
        description="Evento original serializado, para trazabilidad",
    )
