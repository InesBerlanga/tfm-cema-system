"""Escenario ADS-B — SOLO clasificación de eventos con LLM.

Objetivo:
  - Procesar los 6 eventos crudos iniciales de la cadena parcial ADS-B.
  - Clasificarlos con el LLM real.
  - Guardar los ClassifiedEvent y correlaciones en una BD propia.
  - Escribir un sidecar JSON para que otro script pruebe el predictor sin
    volver a clasificar.

Uso:
    python scenario_adsb_classification_only.py

Después:
    python scenario_adsb_predict_only.py
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pipeline import Pipeline
from schemas import (
    EwDetectionInfo,
    EwSensorInfo,
    EwSignalInfo,
    RawCyberEvent,
    RawEwEvent,
)


HERE = Path(__file__).parent
CONFIG = HERE / "config.json"
DB_PATH = HERE / "scenario_adsb_classified.db"
SIDECAR_PATH = HERE / "scenario_adsb_classified.events.json"


# =============================================================================
# Constantes del escenario
# =============================================================================

AOC_PORTAL_IP = "10.55.20.30"
AOC_HOST = "AOC-PORTAL-LEMD"
ATTACKER_IP = "194.88.105.66"

SDR_LAT = 40.4700
SDR_LON = -3.5650


EXPECTED_SEQUENCE = [
    ("TEW01", "Electromagnetic Reconnaissance", "detect", "ew"),
    ("TEW03", "Direction Finding", "exploit", "ew"),
    ("T1595", "Active Scanning", "reconnaissance", "cyber"),
    ("T1190", "Exploit Public-Facing Application", "initial-access", "cyber"),
    ("T1059", "Command and Scripting Interpreter", "execution", "cyber"),
    ("T1083", "File and Directory Discovery", "discovery", "cyber"),
]


# =============================================================================
# Construcción de eventos crudos con descripciones cortas y dirigidas
# =============================================================================

def build_events(t0: datetime) -> list[tuple[str, str, object]]:
    """Devuelve tupla (domain, expected_technique_id, raw_event)."""

    sensor = EwSensorInfo(
        id="EW-SENSOR-LEMD-01",
        type="SDR",
        lat=SDR_LAT,
        lon=SDR_LON,
    )

    # E1 — TEW01: recon pasivo ADS-B
    e1 = RawEwEvent(
        id="EW-ADSB-01",
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
            "class": "passive_monitoring",
            "severity": "low",
            "affected_system": "ATC-NET-LEMD",
            "summary": (
                "Passive monitoring of ADS-B Extended Squitter traffic on 1090 MHz "
                "was detected from a non-cooperative SDR near the airport. The "
                "platform is only receiving legitimate aircraft transponder messages "
                "and collecting the RF environment. No spoofing, replay or jamming "
                "is observed in this event."
            ),
        }),
    )

    # E2 — TEW03: direction finding
    e2 = RawEwEvent(
        id="EW-ADSB-02",
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
            "class": "direction_finding",
            "severity": "medium",
            "affected_system": "ATC-NET-LEMD",
            "summary": (
                "Direction finding activity was observed against legitimate ADS-B "
                "emitters on 1090 MHz. The adversary platform computed repeated "
                "lines of bearing from aircraft transponder messages to geolocate "
                "real emitters around the airport. This event is focused on "
                "electromagnetic direction finding."
            ),
        }),
    )

    # E3 — T1595: active scanning / recon del portal AOC
    e3 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=8),
        "event": {
            "kind": "alert",
            "category": ["web", "intrusion_detection"],
            "module": "waf",
            "severity": 3,
        },
        "source": {"ip": ATTACKER_IP, "port": 51022},
        "destination": {"ip": AOC_PORTAL_IP, "port": 443},
        "host": {"name": AOC_HOST},
        "rule": {
            "id": "WAF-RECON-12",
            "name": "Active scanning of public AOC portal",
        },
        "message": (
            f"External IP {ATTACKER_IP} performed active scanning of the public "
            f"AOC portal at {AOC_HOST}. The activity included sequential requests "
            "to public API paths, admin endpoints and exposed configuration paths. "
            "No exploit payload, command execution or successful login was observed. "
            "This is active scanning of the AOC web surface."
        ),
    })

    # E4 — T1190: exploit public-facing app
    e4 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=12),
        "event": {
            "kind": "alert",
            "category": ["web", "intrusion_detection"],
            "module": "waf",
            "severity": 5,
        },
        "source": {"ip": ATTACKER_IP, "port": 51277},
        "destination": {"ip": AOC_PORTAL_IP, "port": 443},
        "host": {"name": AOC_HOST},
        "rule": {
            "id": "WAF-EXPLOIT-44",
            "name": "Successful exploitation of public-facing AOC application",
        },
        "message": (
            f"Successful exploitation of the public-facing AOC web portal at "
            f"{AOC_HOST}. The attacker sent a deserialization exploit to the "
            "flight plan upload endpoint and obtained unauthenticated remote code "
            "execution on the web application. This indicates exploitation of a "
            "public-facing application."
        ),
    })

    # E5 — T1059: shell post-exploit
    e5 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=15),
        "event": {
            "kind": "alert",
            "category": ["host", "process"],
            "module": "edr",
            "severity": 5,
        },
        "source": {"ip": ATTACKER_IP, "port": 0},
        "destination": {"ip": AOC_PORTAL_IP, "port": 0},
        "host": {"name": AOC_HOST},
        "process": {
            "name": "sh",
            "parent": {"name": "java"},
            "command_line": "/bin/sh -c 'id; uname -a; hostname; ip addr; ps auxf'",
        },
        "rule": {
            "id": "EDR-SHELL-31",
            "name": "Unexpected shell spawned from web application process",
        },
        "message": (
            f"The AOC web application process on {AOC_HOST} spawned an unexpected "
            "/bin/sh child process. The shell executed commands such as id, uname, "
            "hostname, ip addr and ps. This indicates use of a command and scripting "
            "interpreter after exploitation."
        ),
    })

    # E6 — T1083: file and directory discovery
    e6 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=18),
        "event": {
            "kind": "alert",
            "category": ["host", "file"],
            "module": "edr",
            "severity": 4,
        },
        "source": {"ip": ATTACKER_IP, "port": 0},
        "destination": {"ip": AOC_PORTAL_IP, "port": 0},
        "host": {"name": AOC_HOST},
        "process": {
            "name": "find",
            "parent": {"name": "sh"},
            "command_line": (
                "find /etc/aoc /var/lib/aoc /opt/aoc -type f "
                "\\( -name '*.conf' -o -name '*.yml' -o -name '*.properties' \\)"
            ),
        },
        "rule": {
            "id": "EDR-FS-RECON-22",
            "name": "File and directory discovery in AOC host",
        },
        "message": (
            f"A process on {AOC_HOST} executed a recursive filesystem search across "
            "/etc/aoc, /var/lib/aoc and /opt/aoc. The command listed directories "
            "and files matching configuration and application path patterns. The "
            "activity is broad file and directory enumeration after access, "
            "consistent with File and Directory Discovery."
        ),
    })

    return [
        ("ew", "TEW01", e1),
        ("ew", "TEW03", e2),
        ("cyber", "T1595", e3),
        ("cyber", "T1190", e4),
        ("cyber", "T1059", e5),
        ("cyber", "T1083", e6),
    ]


# =============================================================================
# Utilidades
# =============================================================================

def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


def format_techs(classified) -> str:
    if not classified.techniques:
        return "(none)"
    return ", ".join(
        f"{t.technique_id}[{t.tactic}] conf={t.confidence:.2f}"
        for t in classified.techniques
    )


def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()

    with CONFIG.open("r", encoding="utf-8") as f:
        config_dict = json.load(f)
    config_dict["paths"]["db"] = str(DB_PATH)

    banner(f"STEP 0 — Initialize pipeline (DB: {DB_PATH.name})")
    pipeline = Pipeline(config_dict, base_path=CONFIG.parent)
    print("  Pipeline ready. This script WILL call the classification LLM.")

    t0 = datetime.now(timezone.utc) - timedelta(minutes=22)
    events = build_events(t0)

    banner(f"STEP 1 — Classify {len(events)} raw ADS-B/AOC events")

    classified_event_ids: list[str] = []
    classification_report = []

    for idx, (domain, expected_id, raw_ev) in enumerate(events, start=1):
        offset_min = int((raw_ev.timestamp - t0).total_seconds() / 60)
        tag = f"{domain:<5} T+{offset_min:>2}min expected={expected_id:<6}"
        start = time.monotonic()

        try:
            if domain == "cyber":
                classified, new_corrs = pipeline.process_cyber(raw_ev)
            else:
                classified, new_corrs = pipeline.process_ew(raw_ev)
        except Exception as exc:
            elapsed = time.monotonic() - start
            print(f"  [{idx}] {tag} → FAILED {type(exc).__name__}: {exc} ({elapsed:.1f}s)")
            classification_report.append({
                "idx": idx,
                "domain": domain,
                "expected": expected_id,
                "event_id": None,
                "actual": [],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue

        elapsed = time.monotonic() - start
        actual_ids = [t.technique_id for t in classified.techniques]
        ok = expected_id in actual_ids
        mark = "✓" if ok else "✗"

        print(f"  [{idx}] {tag} → {format_techs(classified)} ({elapsed:.1f}s) {mark}")
        if new_corrs:
            methods = ", ".join(sorted({c.method for c in new_corrs}))
            print(f"       ⇢ {len(new_corrs)} correlation(s): {methods}")
        if classified.techniques and classified.techniques[0].reasoning:
            rs = classified.techniques[0].reasoning
            print(f"       reasoning: {rs[:160]}{'...' if len(rs) > 160 else ''}")

        classified_event_ids.append(str(classified.event_id))
        classification_report.append({
            "idx": idx,
            "domain": domain,
            "expected": expected_id,
            "event_id": str(classified.event_id),
            "actual": actual_ids,
            "ok": ok,
            "error": None,
        })

    stats = pipeline.storage.stats()
    banner("STEP 2 — Result")
    print(f"  DB: {DB_PATH}")
    print(f"  events_total={stats['events_total']}  correlations_total={stats['correlations_total']}")

    ok_count = sum(1 for r in classification_report if r["ok"])
    print(f"  expected techniques matched: {ok_count}/{len(classification_report)}")

    sidecar = {
        "scenario": "adsb_partial_prediction",
        "db": DB_PATH.name,
        "event_ids": classified_event_ids,
        "expected_sequence": [
            {"technique_id": tid, "name": name, "tactic": tactic, "domain": dom}
            for tid, name, tactic, dom in EXPECTED_SEQUENCE
        ],
        "classification_report": classification_report,
    }
    SIDECAR_PATH.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    print(f"  sidecar written: {SIDECAR_PATH}")
    print("\n  Next: run `python scenario_adsb_predict_only.py` to test the predictor using this DB.")


if __name__ == "__main__":
    main()
