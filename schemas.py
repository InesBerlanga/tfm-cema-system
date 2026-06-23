"""Esquemas de datos del sistema.

Define los contratos entre módulos:

- RawCyberEvent: evento ciber EN FORMATO ECS (Elastic Common Schema).
  Lo que se asume que llega del SIEM/IDS.
- RawEwEvent: evento EW en formato propio (sensor + signal + detection).
  Lo que se asume que llega de un sensor RF / SIGINT.
- TechniqueAssignment: técnica identificada con UNA táctica concreta y
  confianza.
- ClassifiedEvent: evento normalizado y clasificado. Lleva campos extraídos
  del raw (asset_id, user_id, location, artifacts) para que las reglas de
  correlación accedan a ellos sin navegar la estructura anidada.
- Correlation: vínculo entre dos ClassifiedEvent detectado por una regla.
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Sub-modelos del Cyber Event (ECS / Elastic Common Schema)
# ============================================================================
# Modelamos solo el subset de ECS que el clasificador necesita. ECS define
# cientos de campos opcionales; con extra="ignore" toleramos campos extra
# que no modelamos sin reventar la validación.

class ECSEvent(BaseModel):
    """Sección `event.*` de ECS."""
    kind: Optional[str] = None
    category: list[str] = Field(default_factory=list)
    severity: Optional[int] = Field(default=None, ge=1, le=7)
    module: Optional[str] = None
    dataset: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class ECSEndpoint(BaseModel):
    """Usado para `source.*` y `destination.*` de ECS."""
    ip: Optional[str] = None
    port: Optional[int] = None

    model_config = ConfigDict(extra="ignore")


class ECSHost(BaseModel):
    """Sección `host.*` de ECS. host.name es el activo afectado."""
    name: Optional[str] = None
    id: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class ECSRule(BaseModel):
    """Sección `rule.*` de ECS (regla del IDS que disparó)."""
    id: Optional[str] = None
    name: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# Sub-modelos del EW Event (formato propio)
# ============================================================================
# Tres bloques: quién observó (sensor), qué se observó (signal),
# qué se cree que es (detection). extra="forbid" porque el formato lo
# definimos nosotros y queremos enterarnos si algo cambia.

class EwSensorInfo(BaseModel):
    id: str
    type: str
    lat: Optional[float] = None
    lon: Optional[float] = None

    model_config = ConfigDict(extra="forbid")


class EwSignalInfo(BaseModel):
    freq_mhz: Optional[float] = None
    bw_mhz: Optional[float] = None
    power_dbm: Optional[float] = None
    duration_s: Optional[float] = None
    doa_deg: Optional[float] = Field(default=None, ge=0, le=360)

    model_config = ConfigDict(extra="forbid")


class EwDetectionInfo(BaseModel):
    # 'class' es palabra reservada en Python; usamos alias.
    detection_class: str = Field(alias="class")
    severity: str  # "low" | "medium" | "high" | "critical"
    affected_system: Optional[str] = None
    summary: str

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


# ============================================================================
# Eventos crudos (lo que entra al clasificador)
# ============================================================================

class RawCyberEvent(BaseModel):
    """Evento ciber en formato ECS.

    El campo ECS @timestamp lleva @ que no es un nombre Python válido, por
    eso lo declaramos como `timestamp` con alias.
    """
    timestamp: datetime = Field(alias="@timestamp")
    event: ECSEvent
    source: ECSEndpoint = Field(default_factory=ECSEndpoint)
    destination: ECSEndpoint = Field(default_factory=ECSEndpoint)
    host: ECSHost = Field(default_factory=ECSHost)
    rule: Optional[ECSRule] = None
    user: Optional[dict] = None
    process: Optional[dict] = None
    file: Optional[dict] = None        # ECS file.* (hashes, paths)
    dns: Optional[dict] = None         # ECS dns.* (questions)
    message: str = ""
    # Identificador interno del sistema (no viene de ECS)
    event_id: UUID = Field(default_factory=uuid4)

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class RawEwEvent(BaseModel):
    """Evento EW en formato propio."""
    id: str
    timestamp: datetime
    sensor: EwSensorInfo
    signal: EwSignalInfo
    detection: EwDetectionInfo
    event_id: UUID = Field(default_factory=uuid4)

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# Salida del clasificador
# ============================================================================

class TechniqueAssignment(BaseModel):
    """Una técnica identificada en un evento, con UNA táctica elegida.

    El LLM elige una única táctica entre las que el catálogo lista para esa
    técnica. Esto evita tener que iterar combinaciones aguas abajo en las
    reglas.
    """
    technique_id: str = Field(description="ID del catálogo (ej. T1059, TEW01)")
    technique_name: str
    tactic: str = Field(
        description="UNA táctica de la técnica, elegida por el LLM según el contexto"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(default="", description="Breve justificación")


class ClassifiedEvent(BaseModel):
    """Evento normalizado y clasificado, listo para entrar al correlador.

    Los campos asset_id, user_id, location y artifacts se extraen del raw
    durante la clasificación para que las reglas de correlación no tengan
    que navegar la estructura anidada (ECS o EW propia).
    """
    event_id: UUID
    timestamp: datetime
    domain: Literal["cyber", "ew"]
    techniques: list[TechniqueAssignment]
    asset_id: Optional[str] = Field(
        default=None,
        description="Activo afectado, extraído del raw durante la clasificación.",
    )
    user_id: Optional[str] = Field(
        default=None,
        description="Identidad de usuario asociada al evento (sólo cyber típicamente).",
    )
    location: Optional[tuple[float, float]] = Field(
        default=None,
        description="(lat, lon) si el evento lleva geolocalización (sensores EW).",
    )
    artifacts: list[str] = Field(
        default_factory=list,
        description=(
            "Indicadores observables (IPs, hashes, dominios) en formato "
            "'tipo:valor', por ejemplo 'ip:1.2.3.4', 'hash:abcd…', 'domain:c2.example.com'."
        ),
    )
    classifier_model: str
    classification_ts: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    raw: dict = Field(default_factory=dict, description="Evento original serializado")


# ============================================================================
# Salida del correlador
# ============================================================================

CorrelationMethod = Literal[
    "kill_chain",            # R1: cadena unificada (intra y cross-dominio)
    "cross_domain",          # R2: mapeo doctrinal EW↔MITRE
    "asset_convergence",     # R3: mismo activo
    "geo_proximity",         # R5: proximidad geográfica (EW)
    "shared_artifact",       # R6: IoC compartido (incluye usuario en activos distintos)
]


class Correlation(BaseModel):
    """Vínculo entre dos ClassifiedEvent detectado por una regla.

    Por convención event_a es el MÁS ANTIGUO en el tiempo, event_b el más
    reciente.

    El campo `score` representa EVIDENCIA PURA de esa regla en [0, 1].
    El decaimiento temporal y la confianza del clasificador se aplican
    globalmente en el motor al calcular la `strength` agregada del par.
    """
    correlation_id: UUID = Field(default_factory=uuid4)
    event_a_id: UUID
    event_b_id: UUID
    method: CorrelationMethod
    score: float = Field(ge=0.0, le=1.0)
    delta_t_s: float = Field(ge=0)
    distance_m: Optional[float] = Field(default=None, ge=0)
    metadata: dict = Field(default_factory=dict)
    created_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))