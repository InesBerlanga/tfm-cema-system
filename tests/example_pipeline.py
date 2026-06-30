"""Demo del Pipeline cargando todo desde config.json.

Equivalente funcional a example_engine.py pero usando la clase Pipeline en
lugar de cablear engine, rules, storage a mano. Usa process_classified() para
no depender del LLM (eventos construidos sintéticamente).

Para probar con eventos reales (que pasen por el LLM):

    pipeline = Pipeline.from_config("config.json")

    raw_cyber_event = RawCyberEvent(...)   # ECS
    classified, corrs = pipeline.process_cyber(raw_cyber_event)

    raw_ew_event = RawEwEvent(...)
    classified, corrs = pipeline.process_ew(raw_ew_event)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import sys


_ROOT = Path(__file__).parent.parent  # tests/ -> repo root
sys.path.insert(0, str(_ROOT / 'src' / 'modules'))
sys.path.insert(0, str(_ROOT / 'src'))
from pipeline import Pipeline
from schemas import ClassifiedEvent, TechniqueAssignment


HERE = Path(__file__).parent.parent
CONFIG = HERE / "config.json"
CONFIG_NOLLM = HERE / "config_noLLM.json"


def make_event(
    *,
    domain: str,
    timestamp: datetime,
    techniques: list[tuple[str, str, str, float]],
    asset_id: str | None = None,
    user_id: str | None = None,
    location: tuple[float, float] | None = None,
    artifacts: list[str] | None = None,
) -> ClassifiedEvent:
    return ClassifiedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        domain=domain,  # type: ignore[arg-type]
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
    # Reiniciar BD para que la demo sea reproducible
    db_path = HERE / "tfm_system.db"
    if db_path.exists():
        db_path.unlink()

    # Construir todo el sistema desde el fichero de configuración.
    # NOTA: aunque process_classified no consume el LLM, instanciar el
    # Pipeline sí crea los clientes ChatOpenAI. Si tu vLLM no está accesible,
    # comenta el bloque [llm] del config.json y simplifica el constructor del
    # Pipeline para que no construya clientes cuando solo necesites el motor.
    pipeline = Pipeline.from_config(CONFIG)

    # Escenario CEMA sintético (6 eventos a lo largo de ~14 minutos)
    t0 = datetime(2026, 6, 20, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            domain="ew", timestamp=t0,
            techniques=[("TEW01", "Electromagnetic Reconnaissance", "detect", 0.85)],
            asset_id="GPS_L1", location=(40.4168, -3.7038),
        ),
        make_event(
            domain="ew", timestamp=t0 + timedelta(minutes=2),
            techniques=[("TEW03", "Direction Finding", "exploit", 0.80)],
            asset_id="GPS_L1", location=(40.4180, -3.7050),
        ),
        make_event(
            domain="cyber", timestamp=t0 + timedelta(minutes=5),
            techniques=[("T1190", "Exploit Public-Facing Application", "initial-access", 0.78)],
            asset_id="NAV-CTRL-01", user_id="alice.operator",
            artifacts=["ip:185.220.101.42", "user:alice.operator"],
        ),
        make_event(
            domain="cyber", timestamp=t0 + timedelta(minutes=7),
            techniques=[
                ("T1071", "Application Layer Protocol", "command-and-control", 0.90),
                ("T1498", "Network Denial of Service", "impact", 0.78),
            ],
            asset_id="NAV-CTRL-01", user_id="alice.operator",
            artifacts=["ip:185.220.101.42", "user:alice.operator"],
        ),
        make_event(
            domain="ew", timestamp=t0 + timedelta(minutes=12),
            techniques=[("TEW06.2", "Barrage Jamming", "degrade-disrupt", 0.92)],
            asset_id="GPS_L1", location=(40.4172, -3.7042),
        ),
        make_event(
            domain="cyber", timestamp=t0 + timedelta(minutes=14),
            techniques=[("T1078", "Valid Accounts", "persistence", 0.82)],
            asset_id="SRV-DB-01", user_id="alice.operator",
            artifacts=["user:alice.operator"],
        ),
    ]

    print("=" * 78)
    print("PIPELINE: PROCESADO DE EVENTOS")
    print("=" * 78)
    for i, ev in enumerate(events, start=1):
        tech_str = ", ".join(f"{t.technique_id}/{t.tactic}" for t in ev.techniques)
        print(f"\n[E{i}] {ev.domain:5s} | {ev.timestamp.strftime('%H:%M:%S')} | "
              f"asset={ev.asset_id} | {tech_str}")
        new_corrs = pipeline.process_classified(ev)
        if not new_corrs:
            print("  (sin correlaciones nuevas)")
            continue
        for c in new_corrs:
            print(f"  + {c.method:20s} score={c.score:.2f}  Δt={c.delta_t_s:>6.1f}s")

    # Ranking final de pares por strength agregada
    print("\n" + "=" * 78)
    print("RANKING DE PARES POR STRENGTH AGREGADA")
    print("=" * 78)
    pairs = []
    for i, ev_a in enumerate(events):
        for ev_b in events[i + 1:]:
            corrs = pipeline.storage.get_correlations_for_pair(
                ev_a.event_id, ev_b.event_id
            )
            if not corrs:
                continue
            strength = pipeline.engine.aggregate_pair_strength(corrs, ev_a, ev_b)
            pairs.append((strength, ev_a, ev_b, corrs))
    pairs.sort(reverse=True, key=lambda x: x[0])
    for strength, ev_a, ev_b, corrs in pairs:
        methods = ", ".join(sorted(c.method for c in corrs))
        idx_a = events.index(ev_a) + 1
        idx_b = events.index(ev_b) + 1
        kind = "CROSS" if ev_a.domain != ev_b.domain else f"intra-{ev_a.domain}"
        print(f"  E{idx_a} ↔ E{idx_b}  {kind:11s}  strength={strength:.3f}  reglas=[{methods}]")

    print("\n" + "=" * 78)
    print("ESTADÍSTICAS")
    print("=" * 78)
    for k, v in pipeline.storage.stats().items():
        print(f"  {k:25s}: {v}")


if __name__ == "__main__":
    main()
