"""Escenario ADS-B — SOLO predictor sobre la cadena parcial ya clasificada.

Este script NO vuelve a clasificar eventos. Lee la BD producida por
scenario_adsb_classification_only.py, extrae la cadena más relevante y llama
únicamente al predictor LLM.

Uso:
    python scenario_adsb_classification_only.py
    python scenario_adsb_predict_only.py
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pipeline import Pipeline


HERE = Path(__file__).parent
CONFIG = HERE / "config.json"
DB_PATH = HERE / "scenario_adsb_classified.db"
SIDECAR_PATH = HERE / "scenario_adsb_classified.events.json"


PLANNED_CONTINUATION = [
    ("T1005", "Data from Local System", "collection", "cyber"),
    ("T1565", "Data Manipulation", "impact", "cyber"),
    ("TEW10", "Meaconing", "deceive", "ew"),
    ("TEW08.2", "Manipulative Deception", "deceive", "ew"),
    ("TEW06", "Electromagnetic Jamming", "degrade-disrupt", "ew"),
    ("T1070", "Indicator Removal", "defense-evasion", "cyber"),
]


def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


def short_event(ev) -> str:
    techs = ", ".join(t.technique_id for t in ev.techniques) or "NO_TECH"
    return f"{ev.timestamp.strftime('%H:%M:%S')} {ev.domain:<5} {techs:<18} asset={ev.asset_id}"


def print_chain(chain) -> None:
    print(f"  Chain {chain.chain_id[:8]}:")
    print(f"    events={chain.event_count} pairs={chain.pair_count} "
          f"total_strength={chain.total_strength:.3f} mean_strength={chain.mean_strength:.3f}")
    print(f"    domains={' + '.join(sorted(chain.domains))} cross_domain={chain.is_cross_domain}")
    print("    Events:")
    for i, ev in enumerate(sorted(chain.events, key=lambda e: e.timestamp), start=1):
        print(f"      E{i}: {short_event(ev)}")
    print("    Pair strengths:")
    events_by_id = {ev.event_id: ev for ev in chain.events}
    for (a_id, b_id), strength in sorted(chain.pair_strengths.items(), key=lambda x: -x[1]):
        ev_a = events_by_id.get(a_id)
        ev_b = events_by_id.get(b_id)
        if not ev_a or not ev_b:
            continue
        pair_corrs = [
            c for c in chain.correlations
            if {c.event_a_id, c.event_b_id} == {a_id, b_id}
        ]
        rules = ", ".join(f"{c.method}:{c.score:.2f}" for c in sorted(pair_corrs, key=lambda c: -c.score))
        print(f"      {short_event(ev_a)}")
        print(f"        -> {short_event(ev_b)}")
        print(f"        pair_strength={strength:.3f}  rules={rules}")


def soft_match(predicted_id: str, planned_id: str) -> bool:
    return (
        predicted_id == planned_id
        or predicted_id.startswith(planned_id + ".")
        or planned_id.startswith(predicted_id + ".")
    )


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(
            f"DB not found: {DB_PATH}\n"
            "Run first: python scenario_adsb_classification_only.py"
        )
    if not SIDECAR_PATH.exists():
        raise SystemExit(
            f"Sidecar not found: {SIDECAR_PATH}\n"
            "Run first: python scenario_adsb_classification_only.py"
        )

    with CONFIG.open("r", encoding="utf-8") as f:
        config_dict = json.load(f)
    config_dict["paths"]["db"] = str(DB_PATH)

    sidecar = json.loads(SIDECAR_PATH.read_text(encoding="utf-8"))
    expected_event_ids = set(sidecar.get("event_ids", []))

    banner(f"STEP 0 — Initialize pipeline using existing DB ({DB_PATH.name})")
    pipeline = Pipeline(config_dict, base_path=CONFIG.parent)
    stats = pipeline.storage.stats()
    print(f"  events_total={stats['events_total']}  correlations_total={stats['correlations_total']}")
    print("  This script does NOT call the classification LLM.")

    banner("STEP 1 — Extract strongest ADS-B partial chain")
    chains = pipeline.chain_extractor.extract(min_pair_strength=0.0, min_events=2)
    if not chains:
        raise SystemExit("No chains extracted from the DB. Check classification/correlation output.")

    # Elegimos la cadena que más eventos del sidecar contiene; empate por strength.
    ranked = []
    for ch in chains:
        ids = {str(ev.event_id) for ev in ch.events}
        overlap = len(ids & expected_event_ids)
        ranked.append((overlap, ch.total_strength, ch))
    ranked.sort(key=lambda x: (-x[0], -x[1]))
    target = ranked[0][2]

    print(f"  chains_detected={len(chains)}")
    print(f"  selected_chain_overlap={ranked[0][0]}/{len(expected_event_ids)}")
    print_chain(target)

    banner("STEP 2 — Predictor LLM on partial chain")
    print("  Querying predictor for next plausible techniques...")
    start = time.monotonic()
    prediction = pipeline.predictor.predict(target, max_predictions=6)
    elapsed = time.monotonic() - start
    print(f"  Done in {elapsed:.1f}s")

    if prediction.overall_reasoning:
        print("\n  Overall reasoning:")
        print(f"    {prediction.overall_reasoning}")

    if not prediction.predictions:
        print("\n  No valid predictions returned.")
        return

    print(f"\n  Top {len(prediction.predictions)} predictions:")
    for i, p in enumerate(prediction.predictions, start=1):
        print(f"    [{i}] {p.technique_id:<9} {p.technique_name}")
        print(f"        domain={p.domain:<5} tactic={p.tactic:<18} probability={p.probability:.2f}")
        print(f"        reasoning={p.reasoning}")

    banner("STEP 3 — Qualitative comparison with planned continuation")
    print("  Planned continuation, not fed to the system:")
    planned_ids = set()
    for tid, name, tactic, domain in PLANNED_CONTINUATION:
        planned_ids.add(tid)
        print(f"    - {tid:<9} {name:<32} tactic={tactic:<18} domain={domain}")

    predicted_ids = {p.technique_id for p in prediction.predictions}
    exact_overlap = predicted_ids & planned_ids
    soft_overlap = {
        pid for pid in predicted_ids
        if any(soft_match(pid, planned) for planned in planned_ids)
    }

    pred_cyber = sum(1 for p in prediction.predictions if p.domain == "cyber")
    pred_ew = sum(1 for p in prediction.predictions if p.domain == "ew")

    print(f"\n  Predicted IDs: {sorted(predicted_ids)}")
    print(f"  Planned IDs:  {sorted(planned_ids)}")
    print(f"  Exact overlap: {sorted(exact_overlap)} ({len(exact_overlap)}/{len(planned_ids)})")
    print(f"  Soft overlap:  {sorted(soft_overlap)} ({len(soft_overlap)}/{len(planned_ids)})")
    print(f"  Domain mix: {pred_cyber} cyber + {pred_ew} EW")

    banner("STEP 4 — Checklist")
    checks = [
        ("The selected chain is cross-domain", target.is_cross_domain),
        ("The selected chain contains at least 5/6 classified ADS-B events", ranked[0][0] >= 5),
        ("Predictor returned at least 4 valid predictions", len(prediction.predictions) >= 4),
        ("Predictions mix cyber and EW", pred_cyber > 0 and pred_ew > 0),
        ("At least one prediction matches the planned continuation", len(soft_overlap) >= 1),
    ]
    for label, ok in checks:
        print(f"  [{'✓' if ok else '✗'}] {label}")

    print(
        "\n  Note: qualitative mismatch is not necessarily a failure. The predictor "
        "may propose doctrinally plausible techniques that are not in the planned list."
    )


if __name__ == "__main__":
    main()
