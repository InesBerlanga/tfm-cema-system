"""Demo de extracción de cadenas sobre el escenario CEMA sintético.

Carga el Pipeline desde config.json, procesa los 6 eventos sintéticos del
escenario CEMA (los mismos de example_pipeline.py), y luego extrae cadenas
con ChainExtractor probando dos umbrales distintos para mostrar cómo el
slider min_pair_strength desconecta enlaces débiles.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from chains import Chain, ChainExtractor
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


def print_chain(chain: Chain, event_index: dict) -> None:
    """Imprime una cadena con sus eventos y pares en formato legible."""
    print(f"  {chain.summary()}")
    print(f"    Eventos: {[event_index[ev.event_id] for ev in chain.events]}")
    print(f"    Activos: {sorted(chain.assets)}")
    print(f"    Tácticas: {sorted(chain.tactics)}")
    print(f"    Cross-domain: {chain.is_cross_domain}")
    print(f"    Pares ({chain.pair_count}):")
    pairs_sorted = sorted(chain.pair_strengths.items(),
                          key=lambda kv: kv[1], reverse=True)
    for (id_a, id_b), strength in pairs_sorted:
        label_a = event_index.get(id_a, "?")
        label_b = event_index.get(id_b, "?")
        # Métodos que dispararon sobre este par
        methods = sorted({
            c.method for c in chain.correlations
            if (c.event_a_id, c.event_b_id) == (id_a, id_b)
            or (c.event_b_id, c.event_a_id) == (id_a, id_b)
        })
        print(f"      {label_a}↔{label_b}  strength={strength:.3f}  reglas={methods}")


def main() -> None:
    # Reset BD para reproducibilidad
    db_path = HERE / "tfm_system.db"
    if db_path.exists():
        db_path.unlink()

    pipeline = Pipeline.from_config(CONFIG)

    # Escenario CEMA: 6 eventos a lo largo de ~14 minutos
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

    # Procesado: carga todos los eventos al motor
    print("=" * 78)
    print("PROCESADO DE EVENTOS")
    print("=" * 78)
    for ev in events:
        pipeline.process_classified(ev)
    print(f"  {pipeline.storage.stats()}")

    # Índice de eventos para imprimir cadenas con etiquetas E1..E6
    event_index = {ev.event_id: f"E{i+1}" for i, ev in enumerate(events)}

    # Extractor de cadenas usando el motor del pipeline
    extractor = ChainExtractor(
        storage=pipeline.storage,
        engine=pipeline.engine,
    )

    # Escenario 1: sin filtro de strength (todas las correlaciones cuentan)
    print("\n" + "=" * 78)
    print("CADENAS — min_pair_strength = 0.00 (sin filtro)")
    print("=" * 78)
    chains_full = extractor.extract(min_pair_strength=0.0, min_events=2)
    print(f"\nDetectadas {len(chains_full)} cadena(s):\n")
    for chain in chains_full:
        print_chain(chain, event_index)
        print()

    # Escenario 2: umbral 0.10 — desconecta enlaces débiles
    print("=" * 78)
    print("CADENAS — min_pair_strength = 0.10 (filtro moderado)")
    print("=" * 78)
    chains_filtered = extractor.extract(min_pair_strength=0.10, min_events=2)
    print(f"\nDetectadas {len(chains_filtered)} cadena(s):\n")
    for chain in chains_filtered:
        print_chain(chain, event_index)
        print()

    # Eventos aislados tras el filtro
    isolated = extractor.get_isolated_event_ids(min_pair_strength=0.10)
    if isolated:
        labels = sorted(event_index.get(eid, str(eid)[:8]) for eid in isolated)
        print(f"Eventos aislados con umbral 0.10: {labels}")
        print(f"  (sus pares cayeron todos por debajo del umbral)")

    # Escenario 3: umbral 0.30 — solo cadenas muy sólidas
    print("\n" + "=" * 78)
    print("CADENAS — min_pair_strength = 0.30 (filtro estricto)")
    print("=" * 78)
    chains_strict = extractor.extract(min_pair_strength=0.30, min_events=2)
    print(f"\nDetectadas {len(chains_strict)} cadena(s):\n")
    for chain in chains_strict:
        print_chain(chain, event_index)
        print()


if __name__ == "__main__":
    main()
