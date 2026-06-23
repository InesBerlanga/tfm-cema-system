"""End-to-end test del pipeline CON el LLM real.

Escenario: ataque coordinado MMSI spoofing + intrusión BD del TMS.
Un adversario combina dos pistas paralelas para que el buque MV TARIFA STAR
(MMSI 224178923) desaparezca simultáneamente del espacio RF y de la base
de datos del Vessel Traffic Service (VTS):

  Cyber:   exploit portal → robo credenciales → DELETE en BD → borrado logs
  EW:      recon AIS → direction finding → meaconing → jamming

Los 8 eventos llegan al sistema en orden cronológico intercalado:

  T+0min   cyber  T1190 Exploit Public-Facing Application (initial-access)      exploit en portal web del TMS
  T+2min   ew     TEW01 Reconnaissance (detect)                                 SDR adversario escuchando AIS
  T+5min   cyber  T1078 valid-accounts (initial-access)                         login con credenciales robadas
  T+7min   ew     TEW03 Direction Finding (exploit)                             DF localizando al buque víctima
  T+10min  ew     TEW10 Meaconing (deceive)                                     meaconing — MMSI conflict en RF
  T+13min  cyber  T1565 Data Manipulation (impact)                              DELETE de tracking records
  T+15min  ew     TEW06.2 Barrage Jamming (degrade-disrupt)                       jamming barrage en banda AIS
  T+17min  cyber  T1070 Indicator removal (defense-evasion)                     truncado del audit log

Verificas:
  ✓ Las 8 raw events se clasifican (LLM extrae técnicas válidas del catálogo)
  ✓ Se generan correlaciones (kill_chain, asset_convergence, cross_domain,
    shared_artifact ip)
  ✓ Se extrae una cadena cross-domain conectada
  ✓ El predictor sugiere continuaciones plausibles
  ✓ El recomendador devuelve contramedidas

REQUIERE: vLLM accesible (config.json en llm.cyber / llm.ew / llm.predictor).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from pipeline import Pipeline
from schemas import (
    ECSEndpoint, ECSEvent, ECSHost, ECSRule,
    EwDetectionInfo, EwSensorInfo, EwSignalInfo,
    RawCyberEvent, RawEwEvent,
)


HERE = Path(__file__).parent
CONFIG = HERE / "config.json"


# ============================================================================
# Constructores de los 8 eventos crudos
# ============================================================================

def build_cyber_events(t0: datetime) -> list[RawCyberEvent]:
    """4 eventos cyber: T1190 → T1078 → T1565 → T1070."""
    attacker_ip = "185.220.101.42"   # IP del adversario (saltará shared_artifact)
    legit_user  = "j.martinez"       # cuenta legítima comprometida

    # E1 (T+0min) — exploit en el portal web AIS del TMS
    e1 = RawCyberEvent.model_validate({
        "@timestamp": t0,
        "event": {
            "kind": "alert", "category": ["intrusion_detection"],
            "module": "ids", "severity": 4,
        },
        "source":      {"ip": attacker_ip, "port": 41822},
        "destination": {"ip": "10.20.30.40", "port": 443},
        "host":        {"name": "TMS-WEB-PORTAL"},
        "rule": {"id": "10421",
                 "name": "Web Application Attack - SQLi attempt on AIS query endpoint"},
        "message": (
            "Multiple SQL injection attempts on /ais-portal/api/vessels endpoint "
            "from external IP 185.220.101.42. Payload pattern matches known exploit "
            "for the maritime traffic portal CVE-2024-XXXX (UNION SELECT bypassing "
            "the WHERE clause to dump vessel records). User-Agent: sqlmap/1.6.7. "
            "Five attempts in 90 seconds, last one successful (HTTP 200 returning "
            "DB error in body). Suspected initial reconnaissance/access against "
            "the public-facing TMS portal."
        ),
    })

    # E3 (T+5min) — login en la consola admin de la BD con credenciales robadas
    e3 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=5),
        "event": {
            "kind": "alert", "category": ["authentication", "iam"],
            "module": "siem", "dataset": "auth_logs", "severity": 4,
        },
        "source":      {"ip": attacker_ip, "port": 52341},
        "destination": {"ip": "10.50.10.20", "port": 5432},
        "host":        {"name": "TMS-DB-01"},
        "user":        {"name": legit_user},
        "rule": {"id": "AUTH-203",
                 "name": "Successful login from non-corporate IP range"},
        "message": (
            "Successful interactive login to the TMS database administration console "
            "using the legitimate account j.martinez from external IP 185.220.101.42. "
        ),
    })

    # E6 (T+13min) — DELETE de los tracking records del buque legítimo
    e6 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=13),
        "event": {
            "kind": "alert", "category": ["database", "intrusion_detection"],
            "module": "database_audit", "severity": 5,
        },
        "source":      {"ip": "10.50.10.20"},           # interna (sesión legítima)
        "destination": {"ip": "10.50.10.20"},
        "host":        {"name": "TMS-DB-01"},
        "user":        {"name": legit_user},
        "rule": {"id": "DB-ANOM-301",
                 "name": "Unauthorized modification on critical table"},
        "message": (
            "User j.martinez executed unauthorized UPDATE statements on the "
            "vessels_tracking table for MMSI 224178923, registered to MV TARIFA STAR. "
            "Existing tracking records were modified outside the normal ingestion workflow: "
            "latitude, longitude, timestamp and track_status fields were altered"
        ),
    })

    # E8 (T+17min) — truncado del audit log para borrar evidencia
    e8 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=17),
        "event": {
            "kind": "alert", "category": ["file", "intrusion_detection"],
            "module": "endpoint_security", "severity": 4,
        },
        "host": {"name": "TMS-DB-01"},
        "user": {"name": legit_user},
        "file": {
            "path": "/var/log/database/audit.log",
            "action": "truncate",
        },
        "process": {"name": "bash", "pid": 18242},
        "rule": {"id": "FILE-INT-105",
                 "name": "Audit log tampering — truncate of protected file"},
        "message": (
            "The database audit log file /var/log/database/audit.log was truncated "
            "to zero bytes by an interactive bash session running as j.martinez "
            "with elevated privileges. Backup rotation file audit.log.1 was also "
            "overwritten with empty content immediately afterwards. No legitimate "
            "log rotation job was scheduled at this time. Action is consistent "
            "with anti-forensic cleanup performed after a database manipulation "
            "operation to remove the digital evidence trail."
        ),
    })

    return [e1, e3, e6, e8]


def build_ew_events(t0: datetime) -> list[RawEwEvent]:
    """4 eventos EW: TEW01 → TEW03 → TEW10 → TEW06.2.

    Todos comparten affected_system='AIS-NET-A' (asset_convergence) y se
    observan desde el mismo sensor SDR costero (geo_proximity entre ellos).
    """
    # Sensor único, observando en la bocana del puerto de Algeciras
    sensor = EwSensorInfo(
        id="AIS-RX-SENSOR-01",
        type="SDR",
        lat=36.1278,
        lon=-5.4319,
    )

    # E2 (T+2min) — recon: emisor pasivo offshore escuchando AIS
    e2 = RawEwEvent(
        id="EW-2026-06-21-001",
        timestamp=t0 + timedelta(minutes=2),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=161.975,    # AIS canal A
            bw_mhz=0.025,
            power_dbm=-85.0,
            duration_s=60.0,
            doa_deg=270.0,       # offshore (no hay estación AIS conocida ahí)
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "passive_emission",
            "severity": "medium",
            "affected_system": "AIS-NET-A",
            "summary": (
                "Sustained narrow-band reception activity detected on AIS "
                "channel A (161.975 MHz) from DoA 270°, approximately 5 km "
                "offshore from the sensor. No registered AIS shore or buoy "
                "station exists at that bearing. The signature is consistent "
                "with a mobile receiver passively monitoring AIS traffic in "
                "the operational area — likely electromagnetic reconnaissance "
                "by an external party gathering MMSI patterns of vessels "
                "transiting the strait."
            ),
        }),
    )

    # E4 (T+7min) — direction finding sobre el tráfico AIS
    e4 = RawEwEvent(
        id="EW-2026-06-21-002",
        timestamp=t0 + timedelta(minutes=7),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=161.975,
            bw_mhz=0.030,
            power_dbm=-82.0,
            duration_s=8.0,
            doa_deg=275.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "direction_finding",
            "severity": "medium",
            "affected_system": "AIS-NET-A",
            "summary": (
                "Nearby mobile emitter detected performing rapid bearing "
                "measurements on AIS Class A transmissions in the area. "
                "Eight successive directional acquisitions logged in 8 "
                "seconds, with the antenna sweep pattern consistent with "
                "active target localization rather than wide-area monitoring. "
                "The behaviour follows the earlier passive monitoring activity "
                "(same DoA range) and suggests the adversary has identified a "
                "specific vessel to track precisely — likely preparation for "
                "follow-on spoofing or jamming on that target."
            ),
        }),
    )

    # E5 (T+10min) — meaconing: MMSI conflict observado en RF
    e5 = RawEwEvent(
        id="EW-2026-06-21-003",
        timestamp=t0 + timedelta(minutes=10),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=162.025,         # AIS canal B
            bw_mhz=0.025,
            power_dbm=-68.0,          # más potente que el legítimo (-71dBm)
            duration_s=0.026,         # ráfaga AIS Class A típica
            doa_deg=270.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "mmsi_conflict",
            "severity": "high",
            "affected_system": "AIS-NET-A",
            "summary": (
                "MMSI 224178923 (registered to vessel MV TARIFA STAR) detected "
                "transmitting from DoA 270° (offshore position, ~5 km) at "
                "-68 dBm, while the same MMSI is also actively transmitting "
                "from DoA 95° (port approach lane, the legitimate expected "
                "position) at -71 dBm with 1.4 s time delta between bursts. "
                "Two simultaneous emitters claiming the same MMSI identifier "
                "is impossible in legitimate operation — this is meaconing or "
                "deliberate spoofing of the AIS identity. The ghost emitter "
                "broadcasts the higher power level, attempting to dominate "
                "downstream receivers."
            ),
        }),
    )

    # E7 (T+15min) — jamming barrage para tapar la señal legítima
    e7 = RawEwEvent(
        id="EW-2026-06-21-004",
        timestamp=t0 + timedelta(minutes=15),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=162.0,           # centrada entre los dos canales AIS
            bw_mhz=0.5,               # 500 kHz: cubre AIS-1 y AIS-2 enteros
            power_dbm=-45.0,          # 30+ dB sobre el ruido AIS habitual
            duration_s=180.0,
            doa_deg=270.0,            # mismo origen que el spoofing
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "barrage_jamming",
            "severity": "critical",
            "affected_system": "AIS-NET-A",
            "summary": (
                "Sustained high-power broadband emission centered on "
                "162.000 MHz with 500 kHz bandwidth, blanketing both AIS-1 "
                "(161.975) and AIS-2 (162.025) maritime channels. Power "
                "level -45 dBm at the receiver is approximately 30 dB above "
                "typical AIS signal levels, completely overpowering legitimate "
                "transmissions. DoA matches the earlier MMSI-spoofing source. "
                "AIS reception is effectively jammed in the entire bay area: "
                "loss of tracking on multiple unrelated vessels confirmed by "
                "the receiver, including the legitimate transmissions from "
                "MV TARIFA STAR that were until now competing with the spoof."
            ),
        }),
    )

    return [e2, e4, e5, e7]


# ============================================================================
# Pretty-printers para verificación manual
# ============================================================================

def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def print_event_classification(idx: int, label: str, classified, elapsed: float) -> None:
    techs = ", ".join(
        f"{t.technique_id}/{t.tactic} (conf {t.confidence:.2f})"
        for t in classified.techniques
    ) if classified.techniques else "(NO TECHNIQUES)"
    print(f"  [{idx}] {label}  →  {techs}")
    print(f"      asset={classified.asset_id or '—'}  "
          f"user={classified.user_id or '—'}  "
          f"artifacts={classified.artifacts or '—'}  "
          f"({elapsed:.1f}s)")
    if classified.techniques and classified.techniques[0].reasoning:
        rs = classified.techniques[0].reasoning
        print(f"      reasoning: {rs[:140]}{'...' if len(rs) > 140 else ''}")


def print_chain_summary(chain) -> None:
    print(f"  Chain {chain.chain_id[:8]}")
    print(f"    events: {chain.event_count}  pairs: {chain.pair_count}  "
          f"strength: {chain.total_strength:.3f}")
    print(f"    duration: {int(chain.duration_s)}s  "
          f"domains: {' + '.join(sorted(chain.domains))}  "
          f"cross-dom: {chain.is_cross_domain}")
    print(f"    tactics: {sorted(chain.tactics)}")
    print(f"    assets:  {sorted(chain.assets)}")

    print(f"    Events (chronological):")
    for i, ev in enumerate(sorted(chain.events, key=lambda e: e.timestamp), 1):
        techs_str = ", ".join(t.technique_id for t in ev.techniques)
        print(f"      E{i}  {ev.timestamp.strftime('%H:%M:%S')} "
              f"{ev.domain:<5} {techs_str:<18} asset={ev.asset_id}")

    # Correlaciones agrupadas por método
    by_method: dict[str, int] = {}
    for c in chain.correlations:
        by_method[c.method] = by_method.get(c.method, 0) + 1
    print(f"    Correlations by method:")
    for method in sorted(by_method):
        print(f"      {method:<22} ×{by_method[method]}")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    db_path = HERE / "tfm_system.db"
    if db_path.exists():
        db_path.unlink()

    banner("STEP 0 — Initialize pipeline")
    pipeline = Pipeline.from_config(CONFIG)
    print("  Pipeline ready. Storage, classifiers, engine, predictor, "
          "recommender all wired.")

    # Anclamos el escenario a 'ahora' para que los filtros temporales de la UI
    # funcionen si después abres el dashboard.
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)

    cyber_events = build_cyber_events(t0)
    ew_events    = build_ew_events(t0)

    # Intercalamos cyber/EW por timestamp para procesarlos en orden temporal
    timeline = sorted(
        [("cyber", ev) for ev in cyber_events]
      + [("ew",    ev) for ev in ew_events],
        key=lambda pair: pair[1].timestamp,
    )

    banner("STEP 1 — Classification (LLM) and correlation")
    print(f"  Processing {len(timeline)} raw events through the LLM classifier")
    print(f"  and correlation engine, in chronological order.\n")

    classified_results = []
    for idx, (dom, raw_ev) in enumerate(timeline, start=1):
        offset = (raw_ev.timestamp - t0).total_seconds() / 60
        label = f"{dom:<5} T+{offset:>4.0f}min"
        start = time.monotonic()
        try:
            if dom == "cyber":
                classified, new_corrs = pipeline.process_cyber(raw_ev)
            else:
                classified, new_corrs = pipeline.process_ew(raw_ev)
            elapsed = time.monotonic() - start
            print_event_classification(idx, label, classified, elapsed)
            if new_corrs:
                print(f"      ⇢ {len(new_corrs)} new correlation(s) created")
            classified_results.append((dom, classified))
        except Exception as e:
            elapsed = time.monotonic() - start
            print(f"  [{idx}] {label}  →  FAILED: {type(e).__name__}: {e}  "
                  f"({elapsed:.1f}s)")
            print("\n  Aborting due to classification failure. Check the LLM "
                  "endpoint and re-run.\n")
            return

    # ----- Stats post-clasificación -----
    stats = pipeline.storage.stats()
    print(f"\n  BD state: {stats['events_total']} events, "
          f"{stats['correlations_total']} correlations stored")

    # ===============================================  STEP 2 — chain extraction
    banner("STEP 2 — Chain extraction")
    chains = pipeline.chain_extractor.extract(
        min_pair_strength=0.0, min_events=2,
    )
    print(f"  {len(chains)} chain(s) detected (no strength filter)")
    if not chains:
        print("  No chains detected. Something is off — check correlation outputs.")
        return

    # Tomamos la más fuerte (debería ser una sola cross-domain con los 8 eventos
    # si todo va bien)
    chains.sort(key=lambda c: -c.total_strength)
    for c in chains:
        print()
        print_chain_summary(c)

    target = chains[0]

    # ===============================================  STEP 3 — prediction (LLM)
    banner("STEP 3 — Prediction (LLM)")
    print(f"  Asking the predictor for the next plausible techniques on the "
          f"strongest chain ({target.chain_id[:8]})...")
    start = time.monotonic()
    try:
        prediction = pipeline.predictor.predict(target, max_predictions=5)
        elapsed = time.monotonic() - start
        print(f"  Done in {elapsed:.1f}s.\n")
        if prediction.overall_reasoning:
            print(f"  Overall reasoning:")
            print(f"    «{prediction.overall_reasoning}»\n")
        if not prediction.predictions:
            print("  (No valid predictions returned. Check the LLM response.)")
        else:
            print(f"  Top {len(prediction.predictions)} predicted next techniques:")
            for i, p in enumerate(prediction.predictions, start=1):
                print(f"    [{i}] {p.technique_id} {p.technique_name}")
                print(f"        domain={p.domain}  tactic={p.tactic}  "
                      f"prob={p.probability:.2f}")
                print(f"        {p.reasoning}")
    except Exception as e:
        print(f"  Prediction failed: {type(e).__name__}: {e}")

    # ============================================  STEP 4 — countermeasures
    banner("STEP 4 — Countermeasures (lookup)")
    rec = pipeline.recommender.recommend(target)
    print(f"  {rec.total_matches} countermeasure(s) returned for the chain.")
    if rec.total_matches:
        print(f"  Reactive: {len(rec.reactive_matches)}  ·  "
              f"Preventive: {len(rec.preemptive_matches)}\n")
        for i, m in enumerate(rec.matches[:8], start=1):
            cm = m.countermeasure
            covers = ", ".join(tc.technique_id for tc in m.covers)
            top = f" [{cm.top_level}]" if cm.top_level else ""
            print(f"    [{i}] {cm.id} {cm.name}{top}  "
                  f"(domain={cm.domain}, priority={m.priority:.1f})")
            print(f"        covers: {covers}")
    if rec.techniques_with_no_match:
        print(f"\n  {len(rec.techniques_with_no_match)} technique(s) without "
              f"cataloged defense:")
        for tc in rec.techniques_with_no_match:
            print(f"    - {tc.technique_id} {tc.technique_name} "
                  f"({tc.domain}, {tc.source})")

    # ============================================  STEP 5 — verification hints
    banner("STEP 5 — Verification checklist")
    checks = [
        ("All 8 raw events classified",
         len(classified_results) == 8),
        ("All classified events received at least 1 technique",
         all(c.techniques for _, c in classified_results)),
        ("At least one chain extracted",
         len(chains) >= 1),
        ("Strongest chain is cross-domain",
         target.is_cross_domain),
        ("Strongest chain contains ≥ 6 of the 8 events",
         target.event_count >= 6),
        ("Predictor returned ≥ 1 prediction",
         len(prediction.predictions) >= 1 if 'prediction' in dir() else False),
        ("Recommender returned ≥ 1 countermeasure",
         rec.total_matches >= 1),
    ]
    for label, ok in checks:
        mark = "✓" if ok else "✗"
        print(f"  [{mark}] {label}")

    print(
        "\n  Next steps:\n"
        "    - Lanza la UI: `streamlit run app.py`. La BD ya tiene los 8 "
        "eventos.\n"
        "    - En el sidebar selecciona el time window 1h (los eventos están "
        "anclados a 'ahora -20min').\n"
        "    - En la página Incidents pincha el incidente y comprueba el "
        "grafo + pulsa 'Run LLM prediction'.\n"
        "    - En la página Events filtra por technique='T1565' o 'TEW10' "
        "para ver el detalle de los eventos clave.\n"
    )


if __name__ == "__main__":
    main()
