"""Clasificador de eventos ciber contra MITRE ATT&CK.

Asume que los eventos llegan en formato ECS (Elastic Common Schema).
Lee los campos relevantes de la estructura anidada y los renderiza al LLM.
"""

from typing import Optional

from classifier_base import BaseTechniqueClassifier, _clean_description
from schemas import RawCyberEvent


CYBER_ROLE = """You are a senior cybersecurity analyst expert in MITRE ATT&CK.
Your task is to identify which MITRE ATT&CK techniques are being used in
the cyber event described to you.

Consider the full MITRE tactic cycle (reconnaissance, initial-access,
execution, persistence, privilege-escalation, defense-evasion, credential-access,
discovery, lateral-movement, collection, command-and-control, exfiltration,
impact, etc.).

When a MITRE technique is associated with multiple tactics, pick the ONE
tactic that best matches the context of this specific event.

An event may involve 0, 1, or several techniques. Be conservative: if the
evidence is unclear, do not assign the technique. Precision is more important
than recall."""


class CyberClassifier(BaseTechniqueClassifier):
    domain = "cyber"

    # Usuarios genéricos que aparecen en muchos hosts sin identificar a un actor.
    # Cuando event.user.name cae en este conjunto NO entra como artefacto en
    # la lista (porque dispararía R6 SharedArtifact por coincidencias triviales
    # entre hosts no relacionados). El nombre crudo SÍ se preserva en
    # ClassifiedEvent.user_id para uso en visualización y auditoría.
    # Comparación case-insensitive: la lista vive en minúsculas.
    GENERIC_USERS: set[str] = {
        "admin", "administrator", "root", "system",
        "nt authority\\system", "iusr", "guest", "anonymous",
        "service", "daemon", "nobody", "www-data",
        "postgres", "mysql", "mssql", "oracle",
    }

    def _system_role(self) -> str:
        return CYBER_ROLE

    def _format_catalog(self) -> str:
        """Una línea por técnica con ID, nombre, tácticas y descripción corta."""
        lines = []
        for t in self.catalog:
            tactics = ", ".join(t.get("tactics", [])) or "?"
            desc = _clean_description(t.get("description") or "")
            lines.append(
                f"- {t['id']} | {t['name']} | tactics: {tactics} | {desc}"
            )
        return "\n".join(lines)

    def _format_event(self, event: RawCyberEvent) -> str:
        """Renderiza un evento ECS a texto legible para el LLM."""
        parts = [f"Timestamp: {event.timestamp.isoformat()}"]

        # event.* (ECS event metadata)
        if event.event.module:
            parts.append(f"Source module: {event.event.module}")
        if event.event.dataset:
            parts.append(f"Dataset: {event.event.dataset}")
        if event.event.category:
            parts.append(f"Categories: {', '.join(event.event.category)}")
        if event.event.severity is not None:
            parts.append(f"Severity (ECS 1-7): {event.event.severity}")

        # source / destination IPs
        if event.source.ip:
            src = f"{event.source.ip}"
            if event.source.port:
                src += f":{event.source.port}"
            parts.append(f"Source: {src}")
        if event.destination.ip:
            dst = f"{event.destination.ip}"
            if event.destination.port:
                dst += f":{event.destination.port}"
            parts.append(f"Destination: {dst}")

        # host (el activo afectado)
        if event.host.name:
            parts.append(f"Affected host: {event.host.name}")

        # rule (regla del IDS que disparó)
        if event.rule and event.rule.name:
            parts.append(f"Detection rule: {event.rule.name}")

        # user, process (datos contextuales)
        if event.user:
            parts.append(f"User context: {event.user}")
        if event.process:
            parts.append(f"Process context: {event.process}")

        # message: descripción libre
        if event.message:
            parts.append(f"\nDescription:\n{event.message}")

        return "\n".join(parts)

    # ---------- Extractores específicos para correlación ----------

    def _extract_asset_id(self, event: RawCyberEvent) -> Optional[str]:
        """En ECS el activo es host.name (preferido) o host.id."""
        return event.host.name or event.host.id

    def _extract_user_id(self, event: RawCyberEvent) -> Optional[str]:
        """ECS ubica el usuario en event.user.name. Se ignora si llega vacío
        o si event.user no es un dict (la estructura podría ser anidada en
        algunos productores; aquí solo aceptamos el caso simple).
        """
        if not event.user or not isinstance(event.user, dict):
            return None
        name = event.user.get("name")
        if not name:
            return None
        name = str(name).strip()
        return name or None

    def _extract_location(self, event: RawCyberEvent) -> Optional[tuple[float, float]]:
        """Los eventos ciber ECS no suelen llevar coordenadas. Devolvemos
        None salvo que en el futuro se quiera leer source.geo.location.
        """
        return None

    def _extract_artifacts(self, event: RawCyberEvent) -> list[str]:
        """Extrae IoCs y artefactos pseudo-IoC del evento.

        Formato 'tipo:valor':
          - 'ip:<addr>'      : event.destination.ip
          - 'hash:<sha256>'  : event.file.hash.{sha256, sha1, md5}
          - 'domain:<fqdn>'  : event.dns.question.name
          - 'user:<name>'    : event.user.name (solo si NO es un usuario genérico
                               como admin/root/SYSTEM/etc.; ver GENERIC_USERS).

        Sobre el usuario: estrictamente no es un IoC clásico (no es infraestructura
        del adversario) pero compartirlo entre eventos en activos distintos es la
        señal canónica de movimiento lateral. R6 sabe filtrar este caso: el
        artefacto 'user' solo cuenta como evidencia si los assets difieren.
        """
        artifacts: list[str] = []

        # IP de destino: indicador más útil (típicamente infra del adversario).
        if event.destination.ip:
            artifacts.append(f"ip:{event.destination.ip}")

        # file.hash.* en ECS
        if event.file and isinstance(event.file, dict):
            hash_block = event.file.get("hash")
            if isinstance(hash_block, dict):
                for algo in ("sha256", "sha1", "md5"):
                    value = hash_block.get(algo)
                    if value:
                        artifacts.append(f"hash:{value}")

        # dns.question.name en ECS
        if event.dns and isinstance(event.dns, dict):
            q = event.dns.get("question")
            if isinstance(q, dict):
                name = q.get("name")
                if name:
                    artifacts.append(f"domain:{name}")

        # Usuario (solo si no es genérico). Normalizamos a minúsculas para que
        # 'alice', 'Alice' y 'ALICE' se traten como la misma identidad al hacer
        # intersección entre eventos.
        if event.user and isinstance(event.user, dict):
            user_name = event.user.get("name")
            if user_name:
                normalized = str(user_name).strip().lower()
                if normalized and normalized not in self.GENERIC_USERS:
                    artifacts.append(f"user:{normalized}")

        return artifacts