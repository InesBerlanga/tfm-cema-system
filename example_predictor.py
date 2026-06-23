"""Demo del predictor: dada una cadena CEMA detectada, pide al LLM las
técnicas que podrían venir a continuación.

ATENCIÓN: este ejemplo SÍ llama al LLM (a diferencia de los anteriores que
usaban process_classified). Necesita que tu endpoint vLLM esté accesible.
Si lanzas esto sin red al endpoint, fallará en la llamada a predictor.predict().
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from pipeline import Pipeline
from schemas import ClassifiedEvent, TechniqueAssignment


HERE = Path(__file__).parent
CONFIG = HERE / "config.json"


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
    # Reset BD para reproducibilidad
    db_path = HERE / "tfm_system.db"
    if db_path.exists():
        db_path.unlink()

    pipeline = Pipeline.from_config(CONFIG)

    # Mismos 6 eventos del escenario CEMA
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
    ]

    print("=" * 78)
    print("PROCESADO DE EVENTOS")
    print("=" * 78)
    for ev in events:
        pipeline.process_classified(ev)
    print(f"  Eventos procesados: {len(events)}, "
          f"correlaciones BD: {pipeline.storage.stats()['correlations_total']}")

    # Extraer cadenas (filtro moderado: lo justo para que el escenario quede limpio)
    chains = pipeline.chain_extractor.extract(min_pair_strength=0.10, min_events=2)
    if not chains:
        print("\nNo se detectaron cadenas. Saliendo.")
        return

    print("\n" + "=" * 78)
    print("CADENAS DETECTADAS")
    print("=" * 78)
    for c in chains:
        print(f"  {c.summary()}")
        print(f"    tactics: {sorted(c.tactics)}")

    # Pedimos predicción para la cadena más fuerte
    target_chain = chains[0]
    print("\n" + "=" * 78)
    print(f"PREDICCIÓN PARA LA CADENA: {target_chain.chain_id[:8]}")
    print("=" * 78)
    print(f"  Eventos: {target_chain.event_count}")
    print(f"  Última táctica observada: "
          f"{target_chain.events[-1].techniques[0].tactic if target_chain.events[-1].techniques else '?'}")
    print(f"  Llamando al LLM... (puede tardar unos segundos)\n")

    prediction = pipeline.predictor.predict(target_chain, max_predictions=5)

    print(f"Overall reasoning del LLM:")
    print(f"  «{prediction.overall_reasoning}»\n")

    print(f"Predicciones ({len(prediction.predictions)}):")
    for i, p in enumerate(prediction.predictions, start=1):
        print(f"\n  [{i}] {p.technique_id} {p.technique_name}")
        print(f"      domain={p.domain}  tactic={p.tactic}  prob={p.probability:.2f}")
        print(f"      reasoning: {p.reasoning}")


if __name__ == "__main__":
    main()
