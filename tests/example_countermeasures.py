"""Demo del recomendador de contramedidas.

Procesa el escenario CEMA sintético, extrae la cadena más fuerte, y pide
contramedidas al recomendador en dos modos:

  1. SOLO REACTIVAS: contramedidas para las técnicas YA observadas.
  2. REACTIVAS + PREVENTIVAS: además, contramedidas para técnicas predichas
     (simuladas aquí en lugar de llamar al LLM, para no depender del vLLM).

En tu uso real, el bloque de predicciones lo obtienes con:

    prediction = pipeline.predictor.predict(chain)
    rec = pipeline.recommender.recommend(chain, predictions=prediction.predictions)
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
from predictor import TechniquePrediction
from schemas import ClassifiedEvent, TechniqueAssignment


HERE = Path(__file__).parent.parent
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


def print_recommendation(rec, title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)
    print(f"  Contramedidas recomendadas: {rec.total_matches}")
    if rec.techniques_with_no_match:
        names = [
            f"{tc.technique_id} ({tc.source})"
            for tc in rec.techniques_with_no_match
        ]
        print(f"  Técnicas sin contramedida en catálogo: {names}")

    if not rec.matches:
        return

    # Resumen por dominio
    by_dom = rec.by_domain()
    print(f"\n  Por dominio:  cyber={len(by_dom['cyber'])}  ew={len(by_dom['ew'])}")
    print(f"  Reactivas: {len(rec.reactive_matches)}  Preventivas (solo predichas): {len(rec.preemptive_matches)}")

    print("\n  Top contramedidas (ordenadas por prioridad):")
    for i, m in enumerate(rec.matches[:10], start=1):
        cm = m.countermeasure
        kind = "PREVENTIVA" if m.is_preemptive_only else "REACTIVA"
        cover_str = ", ".join(
            f"{tc.technique_id}({tc.source[:3]})" for tc in m.covers
        )
        top = f" [{cm.top_level}]" if cm.top_level else ""
        print(f"    [{i:2d}] {cm.id} {cm.name}{top}")
        print(f"         domain={cm.domain}  tactics={list(cm.tactics)}  "
              f"priority={m.priority:.1f}  ({kind})")
        print(f"         cubre: {cover_str}")


def main() -> None:
    db_path = HERE / "tfm_system.db"
    if db_path.exists():
        db_path.unlink()

    pipeline = Pipeline.from_config(CONFIG)

    # Mismos 5 eventos del escenario CEMA
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
    for ev in events:
        pipeline.process_classified(ev)

    chains = pipeline.chain_extractor.extract(min_pair_strength=0.1, min_events=2)
    if not chains:
        print("No se detectaron cadenas. Saliendo.")
        return

    target = chains[0]
    print(f"Cadena objetivo: {target.summary()}")
    print(f"  Técnicas observadas: {sorted(target.techniques)}")

    # --- Modo 1: solo reactivas (sin predicciones) ---
    rec_reactive = pipeline.recommender.recommend(target)
    print_recommendation(rec_reactive, "RECOMENDACIONES — solo reactivas")

    # --- Modo 2: reactivas + preventivas usando predicciones SIMULADAS ---
    # En producción harías:  prediction = pipeline.predictor.predict(target)
    #                        predictions = prediction.predictions
    # Aquí inyectamos manualmente predicciones plausibles para no depender del LLM.
    fake_predictions = [
        TechniquePrediction(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="persistence",
            domain="cyber",
            probability=0.70,
            reasoning="Tras compromise inicial, el adversario típicamente persiste con cuentas válidas.",
        ),
        TechniquePrediction(
            technique_id="TEW10",
            technique_name="Meaconing",
            tactic="deceive",
            domain="ew",
            probability=0.55,
            reasoning="Tras jamming GPS, el siguiente paso doctrinal es la suplantación/meaconing.",
        ),
    ]
    rec_full = pipeline.recommender.recommend(target, predictions=fake_predictions)
    print_recommendation(rec_full, "RECOMENDACIONES — reactivas + preventivas (predicciones simuladas)")


if __name__ == "__main__":
    main()
