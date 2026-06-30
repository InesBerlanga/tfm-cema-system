"""Ejemplo end-to-end del motor de correlación.

Construye eventos sintéticos (sin pasar por el LLM) y los procesa por el motor
para mostrar:
  - cómo se generan correlaciones de las distintas reglas
  - cómo el dispatch por applicable_pairs respeta el tipo de par
  - cómo se calcula la fuerza agregada del par cuando varias reglas disparan

El escenario simula una cadena CEMA: reconocimiento EW → exploit EW → ejecución
ciber sobre el mismo activo → C2 cyber → jamming EW degradando el sistema.

Para que sea reproducible sin depender del LLM, construimos directamente
objetos ClassifiedEvent en lugar de partir de RawCyberEvent / RawEwEvent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import sys


_ROOT = Path(__file__).parent.parent  # tests/ -> repo root
sys.path.insert(0, str(_ROOT / 'src' / 'modules'))
sys.path.insert(0, str(_ROOT / 'src'))
from schemas import ClassifiedEvent, TechniqueAssignment
from storage import CorrelationStore
from rules import (
    KillChainRule,
    CrossDomainMappingRule,
    AssetConvergenceRule,
    GeographicProximityRule,
    SharedArtifactRule,
)
from engine import CorrelationEngine


HERE = Path(__file__).parent.parent
KNOWLEDGE = HERE / "knowledge"
DB_PATH = HERE / "tfm_demo.db"


def make_event(
    *,
    domain: str,
    timestamp: datetime,
    techniques: list[tuple[str, str, str, float]],  # [(id, name, tactic, conf)]
    asset_id: str | None = None,
    user_id: str | None = None,
    location: tuple[float, float] | None = None,
    artifacts: list[str] | None = None,
) -> ClassifiedEvent:
    """Helper para construir un ClassifiedEvent sin pasar por el LLM."""
    return ClassifiedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        domain=domain,                       # type: ignore[arg-type]
        techniques=[
            TechniqueAssignment(
                technique_id=tid, technique_name=name,
                tactic=tactic, confidence=conf, reasoning="(synthetic)",
            )
            for (tid, name, tactic, conf) in techniques
        ],
        asset_id=asset_id,
        user_id=user_id,
        location=location,
        artifacts=artifacts or [],
        classifier_model="synthetic",
        raw={},
    )


def main() -> None:
    # ----- Limpiar BD previa para la demo -----
    if DB_PATH.exists():
        DB_PATH.unlink()
    store = CorrelationStore(DB_PATH)

    # ----- Instanciar las 5 reglas con sus configuraciones -----
    rules = [
        KillChainRule(
            tactics_order_path=KNOWLEDGE / "tactics_order.json",
            window_seconds=1800,
        ),
        CrossDomainMappingRule(
            mapping_path=KNOWLEDGE / "ew_mitre_mapping.json",
            window_seconds=3600,
        ),
        AssetConvergenceRule(window_seconds=600),
        GeographicProximityRule(
            max_distance_m=5000, tau_d_m=1000, window_seconds=600,
        ),
        SharedArtifactRule(window_seconds=7200),
    ]

    # ----- Pesos por regla (Σ = 1) -----
    # R6 absorbe el peso que tenía R4: ahora cubre IPs, hashes, dominios y
    # usuarios compartidos en activos distintos (movimiento lateral).
    rule_weights = {
        "kill_chain":        0.30,
        "cross_domain":      0.20,
        "asset_convergence": 0.10,
        "geo_proximity":     0.10,
        "shared_artifact":   0.30,
    }

    engine = CorrelationEngine(
        storage=store,
        rules=rules,
        rule_weights=rule_weights,
        global_tau_t=300.0,
    )

    # ----- Escenario CEMA sintético (5 eventos a lo largo de ~12 minutos) -----
    t0 = datetime(2026, 6, 20, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        # 1) Recon EW: detección de emisiones en banda GPS desde sensor MAD-01.
        make_event(
            domain="ew",
            timestamp=t0,
            techniques=[("TEW01", "Electromagnetic Reconnaissance", "detect", 0.85)],
            asset_id="GPS_L1",
            location=(40.4168, -3.7038),  # Madrid centro
        ),
        # 2) Exploit EW: direction finding sobre la misma banda y zona.
        make_event(
            domain="ew",
            timestamp=t0 + timedelta(minutes=2),
            techniques=[("TEW03", "Direction Finding", "exploit", 0.80)],
            asset_id="GPS_L1",
            location=(40.4180, -3.7050),  # ~150 m del sensor anterior
        ),
        # 3) Cyber initial-access: explotación de aplicación pública (T1190)
        #    sobre el activo NAV-CTRL-01 (dependiente de GPS_L1 doctrinalmente).
        #    Lleva en artifacts tanto la IP destino como el usuario (no genérico).
        make_event(
            domain="cyber",
            timestamp=t0 + timedelta(minutes=5),
            techniques=[("T1190", "Exploit Public-Facing Application", "initial-access", 0.78)],
            asset_id="NAV-CTRL-01",
            user_id="alice.operator",
            artifacts=["ip:185.220.101.42", "user:alice.operator"],
        ),
        # 4) Cyber C2 + Network DoS: comunicación al destino y degradación.
        #    T1498 está en el mapeo doctrinal de TEW06.2, así dispara también R2.
        make_event(
            domain="cyber",
            timestamp=t0 + timedelta(minutes=7),
            techniques=[
                ("T1071", "Application Layer Protocol", "command-and-control", 0.90),
                ("T1498", "Network Denial of Service", "impact", 0.78),
            ],
            asset_id="NAV-CTRL-01",
            user_id="alice.operator",
            artifacts=["ip:185.220.101.42", "user:alice.operator"],
        ),
        # 5) EW jamming sobre la misma banda: el efecto operacional culmina.
        make_event(
            domain="ew",
            timestamp=t0 + timedelta(minutes=12),
            techniques=[("TEW06.2", "Barrage Jamming", "degrade-disrupt", 0.92)],
            asset_id="GPS_L1",
            location=(40.4172, -3.7042),  # cerca de los anteriores EW
        ),
        # 6) Cyber: alice aparece DE NUEVO pero sobre un servidor distinto.
        #    Sin IPs ni hashes compartidos con eventos anteriores: la única
        #    señal es el usuario. R6 dispara con score 0.6 (peso 'user') porque
        #    los assets difieren entre E4 (NAV-CTRL-01) y E6 (SRV-DB-01): es
        #    la señal de movimiento lateral del actor que controla la cuenta.
        make_event(
            domain="cyber",
            timestamp=t0 + timedelta(minutes=14),
            techniques=[("T1078", "Valid Accounts", "persistence", 0.82)],
            asset_id="SRV-DB-01",
            user_id="alice.operator",
            artifacts=["user:alice.operator"],
        ),
    ]

    # ----- Procesar cada evento, mostrar las correlaciones nuevas -----
    print("=" * 78)
    print("PROCESADO DE EVENTOS")
    print("=" * 78)

    for i, ev in enumerate(events, start=1):
        tech_str = ", ".join(f"{t.technique_id}/{t.tactic}" for t in ev.techniques)
        print(f"\n[Evento {i}] {ev.domain:5s} | {ev.timestamp.strftime('%H:%M:%S')} | "
              f"asset={ev.asset_id} | {tech_str}")

        new_corrs = engine.process(ev)
        if not new_corrs:
            print("  (sin correlaciones nuevas)")
            continue
        for c in new_corrs:
            print(f"  + {c.method:25s} score={c.score:.2f}  "
                  f"Δt={c.delta_t_s:>6.1f}s  meta={_short_meta(c.metadata)}")

    # ----- Fuerza agregada de los pares relevantes -----
    print("\n" + "=" * 78)
    print("FUERZA AGREGADA POR PAR (ranking)")
    print("=" * 78)

    pair_results = []
    for i, ev_a in enumerate(events):
        for ev_b in events[i + 1:]:
            corrs = store.get_correlations_for_pair(ev_a.event_id, ev_b.event_id)
            if not corrs:
                continue
            strength = engine.aggregate_pair_strength(corrs, ev_a, ev_b)
            pair_results.append((strength, ev_a, ev_b, corrs))

    pair_results.sort(reverse=True, key=lambda x: x[0])

    for strength, ev_a, ev_b, corrs in pair_results:
        methods = ", ".join(sorted(c.method for c in corrs))
        idx_a = events.index(ev_a) + 1
        idx_b = events.index(ev_b) + 1
        cross = "CROSS" if ev_a.domain != ev_b.domain else "intra"
        print(f"  E{idx_a} ↔ E{idx_b}  {cross}  strength={strength:.3f}  reglas=[{methods}]")

    # ----- Resumen final -----
    print("\n" + "=" * 78)
    print("ESTADÍSTICAS")
    print("=" * 78)
    s = store.stats()
    for k, v in s.items():
        print(f"  {k:25s}: {v}")


def _short_meta(meta: dict) -> str:
    """Renderiza la metadata abreviada en una línea."""
    if not meta:
        return "{}"
    pairs = []
    for k, v in meta.items():
        if isinstance(v, (list, tuple)) and len(v) > 3:
            v = f"[{len(v)} items]"
        elif isinstance(v, str) and len(v) > 24:
            v = v[:21] + "..."
        pairs.append(f"{k}={v}")
    return "{" + ", ".join(pairs) + "}"


if __name__ == "__main__":
    main()
