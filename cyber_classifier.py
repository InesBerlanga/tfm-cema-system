"""Clasificador de eventos ciber contra MITRE ATT&CK."""

from classifier_base import BaseTechniqueClassifier, _clean_description
from schemas import RawCyberEvent


CYBER_ROLE = """You are a senior cybersecurity analyst expert in MITRE ATT&CK.
Your task is to identify which MITRE ATT&CK techniques are being used in
the cyber event described to you.

Consider the full MITRE tactic cycle (reconnaissance, initial-access,
execution, persistence, privilege-escalation, defense-evasion, credential-access,
discovery, lateral-movement, collection, command-and-control, exfiltration,
impact, etc.).

An event may involve 0, 1, or several techniques. Be conservative: if the
evidence is unclear, do not assign the technique. Precision is more important
than recall."""


class CyberClassifier(BaseTechniqueClassifier):
    domain = "cyber"

    def _system_role(self) -> str:
        return CYBER_ROLE

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

    def _format_event(self, event: RawCyberEvent) -> str:
        parts = [
            f"Timestamp: {event.timestamp.isoformat()}",
            f"Source: {event.source}",
        ]
        if event.severity is not None:
            parts.append(f"Reported severity: {event.severity}/5")
        if event.src_ip:
            parts.append(f"Source IP: {event.src_ip}")
        if event.dst_ip:
            parts.append(f"Destination IP: {event.dst_ip}")
        if event.asset_id:
            parts.append(f"Affected asset: {event.asset_id}")
        parts.append(f"\nEvent description:\n{event.raw_text}")
        return "\n".join(parts)
