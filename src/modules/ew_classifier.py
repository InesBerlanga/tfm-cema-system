"""Clasificador de eventos EW contra la matriz de técnicas propia.

Asume que los eventos llegan con la estructura sensor / signal / detection.
"""

from typing import Optional

from classifier_base import BaseTechniqueClassifier, _clean_description
from schemas import RawEwEvent


EW_ROLE = """You are an Electronic Warfare (EW) analyst experienced in
operating RF sensors and characterizing threats in the electromagnetic spectrum.

Your task is to identify which EW techniques are being employed based on the
description of an observed electromagnetic phenomenon and its radiofrequency
parameters.

Techniques are organized by tactics, which are indicated for each entry in
the catalog. When a technique is associated with multiple tactics, pick the
ONE tactic that best matches the context of this specific event.

Always consider the available RF parameters (center frequency, bandwidth,
power, direction of arrival, duration) to discriminate between similar
techniques.

A phenomenon may correspond to 0, 1, or several techniques. Be conservative:
if the evidence is ambiguous, do not assign the technique. Precision is more
important than recall."""


class EwClassifier(BaseTechniqueClassifier):
    domain = "ew"

    def _system_role(self) -> str:
        return EW_ROLE

    def _format_catalog(self) -> str:
        lines = []
        for t in self.catalog:
            tactics = ", ".join(t.get("tactics", [])) or "?"
            desc = _clean_description(t.get("description") or "")
            lines.append(
                f"- {t['id']} | {t['name']} | tactics: {tactics} | {desc}"
            )
        return "\n".join(lines)

    def _format_event(self, event: RawEwEvent) -> str:
        parts = [
            f"Timestamp: {event.timestamp.isoformat()}",
            f"Sensor: {event.sensor.id} (type: {event.sensor.type})",
        ]
        if event.sensor.lat is not None and event.sensor.lon is not None:
            parts.append(
                f"Sensor location: ({event.sensor.lat}, {event.sensor.lon})"
            )

        sig = event.signal
        rf = []
        if sig.freq_mhz is not None:
            rf.append(f"freq={sig.freq_mhz} MHz")
        if sig.bw_mhz is not None:
            rf.append(f"bw={sig.bw_mhz} MHz")
        if sig.power_dbm is not None:
            rf.append(f"power={sig.power_dbm} dBm")
        if sig.duration_s is not None:
            rf.append(f"duration={sig.duration_s} s")
        if sig.doa_deg is not None:
            rf.append(f"DoA={sig.doa_deg}°")
        if rf:
            parts.append(f"RF parameters: {' | '.join(rf)}")

        det = event.detection
        parts.append(f"Detection class: {det.detection_class}")
        parts.append(f"Severity: {det.severity}")
        if det.affected_system:
            parts.append(f"Affected system: {det.affected_system}")
        parts.append(f"\nDescription:\n{det.summary}")

        return "\n".join(parts)

    # ---------- Extractores específicos para correlación ----------

    def _extract_asset_id(self, event: RawEwEvent) -> Optional[str]:
        """En EW el 'activo' es el sistema afectado (GPS_L1, INMARSAT, etc)."""
        return event.detection.affected_system

    def _extract_user_id(self, event: RawEwEvent) -> Optional[str]:
        """Los sensores EW no tienen concepto de usuario; siempre None."""
        return None

    def _extract_location(self, event: RawEwEvent) -> Optional[tuple[float, float]]:
        """(lat, lon) del sensor que observó el fenómeno, si están disponibles."""
        if event.sensor.lat is None or event.sensor.lon is None:
            return None
        return (event.sensor.lat, event.sensor.lon)

    def _extract_artifacts(self, event: RawEwEvent) -> list[str]:
        """Los eventos EW no producen IoCs en el sentido cibernético (hashes,
        IPs, dominios). La regla R6 (SharedArtifact) no aplica a EW.
        """
        return []