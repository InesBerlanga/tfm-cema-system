"""Clasificador de eventos EW contra la matriz de técnicas propia."""

from classifier_base import BaseTechniqueClassifier, _clean_description
from schemas import RawEwEvent


EW_ROLE = """You are an Electronic Warfare (EW) analyst experienced in
operating RF sensors and characterizing threats in the electromagnetic spectrum.

Your task is to identify which EW techniques are being employed based on the
description of an observed electromagnetic phenomenon and its radiofrequency
parameters.

Techniques are organized by tactics, which are indicated for each entry in the
catalog. Always consider the available RF parameters (center frequency,
bandwidth, power, direction of arrival, modulation) to discriminate between
similar techniques.

A phenomenon may correspond to 0, 1, or several techniques. Be conservative:
if the evidence is ambiguous, do not assign the technique. Precision is more
important than recall."""


class EwClassifier(BaseTechniqueClassifier):
    domain = "ew"

    def _system_role(self) -> str:
        return EW_ROLE

    def _format_catalog(self) -> str:
        """One line per technique with ID, name, tactics and short description."""
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
            f"Sensor: {event.source}",
        ]
        rf = []
        if event.freq_center_mhz is not None:
            rf.append(f"Center frequency: {event.freq_center_mhz} MHz")
        if event.bandwidth_khz is not None:
            rf.append(f"Bandwidth: {event.bandwidth_khz} kHz")
        if event.power_dbm is not None:
            rf.append(f"Power: {event.power_dbm} dBm")
        if event.doa_deg is not None:
            rf.append(f"DoA: {event.doa_deg}°")
        if rf:
            parts.append("RF parameters: " + " | ".join(rf))
        if event.location:
            parts.append(f"Location: lat={event.location[0]}, lon={event.location[1]}")
        if event.asset_id:
            parts.append(f"Potentially affected asset: {event.asset_id}")
        parts.append(f"\nPhenomenon description:\n{event.raw_description}")
        return "\n".join(parts)
