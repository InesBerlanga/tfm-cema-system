"""Demo del módulo de storage usando eventos sintéticos.

Sin LLM. Crea ClassifiedEvent a mano (como si saliera del clasificador) y
los guarda en la BD para verificar la capa de persistencia.

Ejecuta:
    python example_storage.py
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import sys


_ROOT = Path(__file__).parent.parent  # tests/ -> repo root
sys.path.insert(0, str(_ROOT / 'src' / 'modules'))
sys.path.insert(0, str(_ROOT / 'src'))
from schemas import ClassifiedEvent, TechniqueAssignment
from storage import CorrelationStore


DB_PATH = Path(__file__).parent.parent / "tfm_system.db"


def make_event(
    seconds_ago: int,
    domain: str,
    techniques: list[tuple[str, str, str, float]],
    asset_id: str = "WS-042",
) -> ClassifiedEvent:
    """Crea un ClassifiedEvent sintético.

    Args:
        seconds_ago: cuántos segundos atrás está el evento.
        domain: 'cyber' o 'ew'.
        techniques: lista de tuplas (technique_id, name, tactic, confidence).
        asset_id: identificador del activo afectado.
    """
    return ClassifiedEvent(
        event_id=uuid4(),
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago),
        domain=domain,
        techniques=[
            TechniqueAssignment(
                technique_id=tid,
                technique_name=tname,
                tactic=tactic,
                confidence=conf,
                reasoning="sintético para demo de storage",
            )
            for tid, tname, tactic, conf in techniques
        ],
        asset_id=asset_id,
        classifier_model="synthetic",
        raw={"note": "evento sintético, sin estructura raw real"},
    )


def main():
    print(f"Inicializando BD en {DB_PATH.resolve()}")
    store = CorrelationStore(DB_PATH)

    print("\nInsertando eventos sintéticos...")
    events = [
        make_event(120, "cyber", [("T1204", "User Execution", "execution", 0.85)]),
        make_event(90, "cyber", [
            ("T1059", "Command and Scripting Interpreter", "execution", 0.9),
            ("T1027", "Obfuscated Files or Information", "defense-evasion", 0.7),
        ]),
        make_event(60, "cyber", [
            ("T1071", "Application Layer Protocol", "command-and-control", 0.9)
        ]),
        # EW: ojo, este usa otro asset_id distinto (GPS_L1).
        # Nota: nombre de táctica en lowercase con guión, alineado con tactics_order.json.
        make_event(75, "ew", [
            ("TEW06.2", "Barrage Jamming", "degrade-disrupt", 0.9)
        ], asset_id="GPS_L1"),
    ]
    for e in events:
        store.save_event(e)
        print(f"  ✓ {e.domain:5s} {e.timestamp.strftime('%H:%M:%S')} "
              f"asset={e.asset_id:8s} {[t.technique_id for t in e.techniques]}")

    print("\nEstadísticas:")
    for k, v in store.stats().items():
        print(f"  {k}: {v}")

    print("\nConsulta de ventana (últimos 3 min):")
    window = store.get_events_in_window(
        center_time=datetime.now(timezone.utc),
        window_seconds=180,
    )
    for e in window:
        tids = ", ".join(t.technique_id for t in e.techniques)
        print(f"  [{e.domain}] {e.timestamp.isoformat(timespec='seconds')} "
              f"asset={e.asset_id} → {tids}")

    print("\nSolo ciber:")
    cyber_only = store.get_events_in_window(
        center_time=datetime.now(timezone.utc),
        window_seconds=180,
        domain="cyber",
    )
    print(f"  {len(cyber_only)} eventos ciber en la ventana")

    print("\nRecuperar evento concreto por ID:")
    sample = events[0]
    recovered = store.get_event(sample.event_id)
    assert recovered is not None
    assert recovered.event_id == sample.event_id
    assert recovered.techniques[0].technique_id == "T1204"
    assert recovered.techniques[0].tactic == "execution"
    print(f"  ✓ Evento {sample.event_id} recuperado, técnica + táctica preservadas")

    print(f"\nBD en {DB_PATH.resolve()}")


if __name__ == "__main__":
    main()