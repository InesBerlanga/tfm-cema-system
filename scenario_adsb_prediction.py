"""Escenario 3 — Cadena parcial ADS-B: test del predictor LLM.

Marco doctrinal
---------------
Aeropuerto bajo amenaza. ADS-B opera en 1090 MHz (Extended Squitter); las
aeronaves emiten posición, velocidad e identificador. Un adversario quiere
inyectar un *ghost track* (aeronave fantasma) para enmascarar una
manipulación posterior en la base de datos del AOC (Aeronautical
Operational Control).

A diferencia del escenario MMSI o el de denegación GNSS+5G, aquí solo se
inyectan los SEIS PRIMEROS EVENTOS del ataque al sistema. El propósito no
es validar la detección de la cadena completa, sino comprobar qué propone
el predictor LLM cuando la cadena está incompleta — qué técnicas anticipa
para las fases de descubrimiento profundo, recolección, impacto y
falsificación que aún no se han producido.

Cadena alimentada (6 eventos)
  T+0min   EW     TEW01    (detect)            recon pasivo ADS-B 1090 MHz
  T+3min   EW     TEW03    (exploit)           DF de emisores legítimos
  T+8min   cyber  T1595    (reconnaissance)    recon portal AOC
  T+12min  cyber  T1190    (initial-access)    exploit del portal AOC
  T+15min  cyber  T1059    (execution)         shell post-exploit en AOC
  T+18min  cyber  T1083    (discovery)         enumeración de paths/configs

Continuación PLANIFICADA pero NO alimentada (referencia cualitativa para
comparar con lo que el LLM prediga):
  - T1005        Data from Local System    (stage del contenido del DB)
  - T1565        Data Manipulation         (modificación de la BD AOC)
  - TEW10        Meaconing                 (ghost track ADS-B)
  - TEW08.2      Manipulative Deception    (data falsification del feed)
  - TEW06        Electromagnetic Jamming   (deniega ADS-B genuino)
  - T1070        Indicator Removal         (anti-forensics)

REQUIERE: vLLM accesible.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pipeline import Pipeline
from schemas import (
    EwDetectionInfo, EwSensorInfo, EwSignalInfo,
    RawCyberEvent, RawEwEvent,
)


HERE = Path(__file__).parent
CONFIG = HERE / "config.json"
DB_PATH = HERE / "scenario_adsb.db"


# ============================================================================
# Constantes del escenario
# ============================================================================

AOC_PORTAL_IP   = "10.55.20.30"
AOC_HOST        = "AOC-PORTAL-LEMD"
ATTACKER_IP     = "194.88.105.66"

# Sensor SDR adversario en las inmediaciones del aeropuerto
SDR_LAT = 40.4700
SDR_LON = -3.5650

# Continuación planificada (no se alimenta, solo se imprime al final
# para comparar con la predicción del LLM)
PLANNED_CONTINUATION = [
    ("T1005",   "Data from Local System",        "collection",         "cyber"),
    ("T1565",   "Data Manipulation",             "impact",             "cyber"),
    ("TEW10",   "Meaconing",                     "deceive",            "ew"),
    ("TEW08.2", "Manipulative Deception",        "deceive",            "ew"),
    ("TEW06",   "Electromagnetic Jamming",       "degrade-disrupt",    "ew"),
    ("T1070",   "Indicator Removal",             "defense-evasion",    "cyber"),
]


# ============================================================================
# Constructores de los 6 eventos
# ============================================================================

def build_events(t0: datetime) -> list:
    sensor = EwSensorInfo(
        id="EW-SENSOR-LEMD-01", type="SDR",
        lat=SDR_LAT, lon=SDR_LON,
    )

    e1 = RawEwEvent(
        id="EW-2026-06-21-ADSB-01",
        timestamp=t0 + timedelta(minutes=0),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=1090.0,
            bw_mhz=2.0,
            power_dbm=-92.0,
            duration_s=240.0,
            doa_deg=180.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "passive_emission",
            "severity": "low",
            "affected_system": "ATC-NET-LEMD",
            "summary": (
                "Persistent passive reception detected in the ADS-B Extended Squitter "
                "band (1090 MHz) from a non-cooperative SDR platform located near "
                "the runway 14L glide path. Pattern consistent with prolonged "
                "collection of legitimate aircraft transponder traffic, almost "
                "certainly a preparation phase for later spoofing or replay "
                "operations against the ADS-B surveillance feed."
            ),
        }),
    )

    e2 = RawEwEvent(
        id="EW-2026-06-21-ADSB-02",
        timestamp=t0 + timedelta(minutes=3),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=1090.0,
            bw_mhz=2.0,
            power_dbm=-88.0,
            duration_s=180.0,
            doa_deg=180.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "active_geolocation",
            "severity": "medium",
            "affected_system": "ATC-NET-LEMD",
            "summary": (
                "Direction-finding activity observed against multiple legitimate "
                "ADS-B emitters on final approach. The adversary platform is "
                "performing line-of-bearing computations across consecutive squitter "
                "messages from several aircraft, characterising the geometry of the "
                "real ADS-B emitter population over the airfield. This precedes the "
                "injection of counterfeit emitters at angles consistent with the "
                "observed pattern."
            ),
        }),
    )

    e3 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=8),
        "event": {
            "kind": "alert", "category": ["web", "intrusion_detection"],
            "module": "waf", "severity": 3,
        },
        "source":      {"ip": ATTACKER_IP, "port": 51022},
        "destination": {"ip": AOC_PORTAL_IP, "port": 443},
        "host":        {"name": AOC_HOST},
        "rule": {"id": "WAF-RECON-12",
                 "name": "Aggressive enumeration of public AOC API endpoints"},
        "message": (
            f"Aggressive enumeration of the AOC public portal at {AOC_HOST} from "
            f"external IP {ATTACKER_IP}. Sequential GET requests against "
            "/aoc-api/v1/flightplans, /aoc-api/v1/surveillance, /admin/login, "
            "/.git/config, and several known administrative paths. User-Agent "
            "rotating across common HTTP libraries. Pattern matches active "
            "reconnaissance of the AOC web surface prior to exploitation."
        ),
    })

    e4 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=12),
        "event": {
            "kind": "alert", "category": ["web", "intrusion_detection"],
            "module": "waf", "severity": 5,
        },
        "source":      {"ip": ATTACKER_IP, "port": 51277},
        "destination": {"ip": AOC_PORTAL_IP, "port": 443},
        "host":        {"name": AOC_HOST},
        "rule": {"id": "WAF-EXPLOIT-44",
                 "name": "Successful exploitation of public-facing AOC application"},
        "message": (
            f"Successful exploitation of the AOC public portal at {AOC_HOST}. "
            "Payload pattern matches a deserialization vulnerability in the flight "
            "plan upload endpoint. Adversary gained an unauthenticated remote code "
            "execution path on the front-end process. The portal is the public "
            "entry point to the AOC backend that feeds surveillance correlation "
            "with the ADS-B receivers being characterised in the RF domain by the "
            "same adversary platform 12 minutes earlier."
        ),
    })

    e5 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=15),
        "event": {
            "kind": "alert", "category": ["host", "process"],
            "module": "edr", "severity": 5,
        },
        "source":      {"ip": ATTACKER_IP, "port": 0},
        "destination": {"ip": AOC_PORTAL_IP, "port": 0},
        "host":        {"name": AOC_HOST},
        "process": {
            "name": "sh",
            "parent": {"name": "java"},
            "command_line": "/bin/sh -c 'id; uname -a; hostname; ip addr; "
                            "ps auxf | head -50'",
        },
        "rule": {"id": "EDR-SHELL-31",
                 "name": "Unexpected shell spawned from web application process"},
        "message": (
            f"Endpoint EDR on {AOC_HOST} flagged the AOC front-end Java process "
            "spawning an interactive /bin/sh child shell, which then issued a "
            "sequence of enumeration commands (id, uname, hostname, ip addr, ps "
            "auxf) within seconds. Web application servers do not legitimately "
            "spawn interactive shells under any normal operating procedure. The "
            "behaviour is consistent with the adversary executing reconnaissance "
            "commands through the remote code execution path obtained 3 minutes "
            "earlier via the deserialization exploit."
        ),
    })

    e6 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=18),
        "event": {
            "kind": "alert", "category": ["host", "file"],
            "module": "edr", "severity": 4,
        },
        "source":      {"ip": ATTACKER_IP, "port": 0},
        "destination": {"ip": AOC_PORTAL_IP, "port": 0},
        "host":        {"name": AOC_HOST},
        "process": {
            "name": "find",
            "parent": {"name": "sh"},
            "command_line": "find /etc/aoc /var/lib/aoc /opt/aoc -type f "
                            "\\( -name '*.conf' -o -name '*.yml' "
                            "-o -name '*.properties' -o -name '*.sql' "
                            "-o -name 'connection*' \\) -printf '%p %s\\n'",
        },
        "rule": {"id": "EDR-FS-RECON-22",
                 "name": "Filesystem reconnaissance — broad config and data path enumeration"},
        "message": (
            f"Process tree on {AOC_HOST} executed an exhaustive filesystem walk "
            "across /etc/aoc, /var/lib/aoc and /opt/aoc looking for configuration "
            "files (*.conf, *.yml, *.properties), SQL artefacts and connection "
            "definition files. The traversal pattern is too broad and too "
            "specific to AOC internal directory layout to be operator-driven. "
            "Consistent with adversary post-access discovery of the AOC backend "
            "structure, in particular the location of database connection "
            "credentials and the flight plan / surveillance data stores."
        ),
    })

    return [
        ("ew",    e1),
        ("ew",    e2),
        ("cyber", e3),
        ("cyber", e4),
        ("cyber", e5),
        ("cyber", e6),
    ]


# ============================================================================
# Visualización
# ============================================================================

def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()

    with CONFIG.open("r", encoding="utf-8") as f:
        config_dict = json.load(f)
    config_dict["paths"]["db"] = str(DB_PATH)

    banner("STEP 0 — Initialize pipeline (DB: scenario_adsb.db)")
    pipeline = Pipeline(config_dict, base_path=CONFIG.parent)

    t0 = datetime.now(timezone.utc) - timedelta(minutes=22)
    events = build_events(t0)

    banner(f"STEP 1 — Process {len(events)} events (cadena alimentada, fase inicial)")
    classified_events = []
    for idx, (domain, raw_ev) in enumerate(events, start=1):
        offset_min = (raw_ev.timestamp - t0).total_seconds() / 60
        tag = f"{domain:<5} T+{offset_min:>4.0f}min"
        start = time.monotonic()
        try:
            if domain == "cyber":
                classified, new_corrs = pipeline.process_cyber(raw_ev)
            else:
                classified, new_corrs = pipeline.process_ew(raw_ev)
            elapsed = time.monotonic() - start
            techs = ", ".join(
                f"{t.technique_id}[{t.tactic}]" for t in classified.techniques
            ) or "(none)"
            print(f"  [{idx}] {tag}  →  {techs}    ({elapsed:.1f}s)")
            if new_corrs:
                methods = ", ".join(sorted({c.method for c in new_corrs}))
                print(f"       ⇢ {len(new_corrs)} correlations: {methods}")
            classified_events.append(classified)
        except Exception as e:
            elapsed = time.monotonic() - start
            print(f"  [{idx}] {tag}  →  FAILED: {type(e).__name__}: {e}  ({elapsed:.1f}s)")
            return

    # ===============================================  STEP 2 — chain extraction
    banner("STEP 2 — Chain extraction")
    chains = pipeline.chain_extractor.extract(min_pair_strength=0.0, min_events=2)
    if not chains:
        print("  No chain extracted from the events. Cannot run predictor.")
        return
    chains.sort(key=lambda c: -c.total_strength)
    target = chains[0]
    print(f"  Strongest chain: {target.event_count} events, "
          f"strength {target.total_strength:.3f}, "
          f"cross-domain={target.is_cross_domain}")
    by_method = {}
    for c in target.correlations:
        by_method[c.method] = by_method.get(c.method, 0) + 1
    print(f"  Correlations by rule: {dict(by_method)}")

    # ===============================================  STEP 3 — predictor
    banner("STEP 3 — Predictor LLM (sobre cadena parcial)")
    print("  Querying predictor for next plausible techniques...")
    start = time.monotonic()
    try:
        prediction = pipeline.predictor.predict(target, max_predictions=6)
        elapsed = time.monotonic() - start
        print(f"  Done in {elapsed:.1f}s\n")
        if prediction.overall_reasoning:
            print(f"  Overall reasoning del LLM:")
            print(f"    «{prediction.overall_reasoning}»\n")
        if not prediction.predictions:
            print("  (No valid predictions returned. Check the LLM response.)")
            return
        print(f"  Top {len(prediction.predictions)} predicciones del LLM:")
        for i, p in enumerate(prediction.predictions, start=1):
            print(f"    [{i}] {p.technique_id} {p.technique_name}")
            print(f"        domain={p.domain}  tactic={p.tactic}  prob={p.probability:.2f}")
            print(f"        reasoning: {p.reasoning}")
    except Exception as e:
        print(f"  Prediction failed: {type(e).__name__}: {e}")
        return

    # ===============================================  STEP 4 — comparación cualitativa
    banner("STEP 4 — Comparación cualitativa con la continuación planificada")
    print("  Continuación PLANIFICADA (no alimentada al sistema):")
    planned_ids = set()
    for tid, name, tactic, dom in PLANNED_CONTINUATION:
        print(f"    - {tid:<10} {name:<28} (tactic={tactic}, {dom})")
        planned_ids.add(tid)

    predicted_ids = {p.technique_id for p in prediction.predictions}
    exact_overlap = predicted_ids & planned_ids
    # Coincidencia "blanda" por raíz (T1565 cubre T1565.001, etc.)
    soft_overlap = set()
    for pid in predicted_ids:
        for planned in planned_ids:
            if pid == planned or pid.startswith(planned + ".") or planned.startswith(pid + "."):
                soft_overlap.add(pid)
                break

    print(f"\n  Predichas: {sorted(predicted_ids)}")
    print(f"  Planificadas: {sorted(planned_ids)}")
    print(f"  Coincidencia exacta: {sorted(exact_overlap)}  "
          f"({len(exact_overlap)}/{len(planned_ids)})")
    print(f"  Coincidencia (incluyendo sub-técnicas): "
          f"{sorted(soft_overlap)}  ({len(soft_overlap)}/{len(planned_ids)})")

    pred_cyber = sum(1 for p in prediction.predictions if p.domain == "cyber")
    pred_ew    = sum(1 for p in prediction.predictions if p.domain == "ew")
    print(f"  Reparto del LLM: {pred_cyber} cyber + {pred_ew} EW "
          f"(cross-domain={'sí' if pred_cyber > 0 and pred_ew > 0 else 'no'})")

    # ===============================================  STEP 5 — checklist
    banner("STEP 5 — Verification checklist")
    checks = [
        ("Los 6 eventos clasificados",
         len(classified_events) == 6),
        ("Cadena cross-domain",
         target.is_cross_domain),
        ("Predictor devuelve ≥ 4 predicciones válidas",
         len(prediction.predictions) >= 4),
        ("Las predicciones mezclan cyber y EW",
         pred_cyber > 0 and pred_ew > 0),
        ("≥1 predicción coincide con la continuación planificada (soft match)",
         len(soft_overlap) >= 1),
        ("≥2 predicciones coinciden con la continuación planificada",
         len(soft_overlap) >= 2),
    ]
    for label, ok in checks:
        print(f"  [{'✓' if ok else '✗'}] {label}")

    print(
        "\n  Nota: la coincidencia cualitativa es informativa, no una métrica de\n"
        "  acierto. Predicciones doctrinalmente coherentes pero no listadas en la\n"
        "  continuación planificada también son resultados válidos del LLM.\n"
    )


if __name__ == "__main__":
    main()