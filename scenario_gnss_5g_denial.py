"""Escenario 2 — Denegación coordinada GNSS + 5G de C2 a unidad terrestre,
con eventos ruido inyectados para verificar que el sistema no los absorbe
en la cadena del ataque.

Marco doctrinal
---------------
La unidad táctica UCT-DELTA-7 (escuadrón mecanizado adelantado) opera en
una zona contestada. Depende de:
  - GNSS L1 (1.575 GHz) para PNT
  - Enlace 5G NSA militar en banda n78 (~3.5 GHz) para C2 backhaul contra
    el gateway C2-GW-DELTA en retaguardia

El adversario quiere desorientar a la unidad y aislarla del C2 para
inyectar pintado operacional falso antes de que reconecte. Combina cuatro
pistas EW (recon GNSS, jamming GNSS, spoofing PNT, jamming 5G) con cuatro
pistas cyber (recon C2, intento C2 alternativo, DoS, manipulación de
dashboard).

Eventos
-------
Cadena de ataque (8 eventos coordinados):
  T+0min   EW     TEW01     (detect)              SDR pasivo escuchando GNSS L1
  T+1min   cyber  T1595     (recon)               scan agresivo al gateway de C2
  T+3min   EW     TEW06.2   (degrade-disrupt)     barrage jamming en 1.575 GHz
  T+5min   cyber  T1071     (command-and-control) C2 alternativo (DNS tunneling)
  T+7min   EW     TEW10     (deceive)             meaconing — replay de GPS falso
  T+10min  cyber  T1499     (impact)              DoS sostenido sobre C2-GW-DELTA
  T+12min  EW     TEW06.2   (degrade-disrupt)     barrage jamming en 5G n78
  T+14min  cyber  T1565     (impact)              manipulación de dashboard C2

Ruido (6 eventos que NO deben entrar en la cadena del ataque):
  T-180min cyber  T1566     phishing contra HR-LAPTOP-23 (fuera de ventanas)
  T-90min  EW     TEW01     escucha en ISM 2.4 GHz a 50 km al norte
  T+6min   cyber  T1071     DNS tunneling en MAIL-SRV-04 (otra IP, otro asset)
  T+9min   EW     TEW01     anomalía WiFi en base camp, otra location
  T+18min  cyber  T1110     brute force contra VPN corporativa
  
REQUIERE: vLLM accesible (config.json apunta a llm.cyber/ew/predictor).
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
DB_PATH = HERE / "scenario_gnss_5g.db"
SIDECAR_PATH = HERE / "scenario_gnss_5g.events.json"


# ============================================================================
# Constantes del escenario
# ============================================================================

# Adversario común para los cyber del ataque (saltará shared_artifact si el
# clasificador llega a registrar la IP de destino del C2)
ATTACKER_IP    = "91.205.144.18"
C2_GATEWAY_IP  = "10.40.50.10"      # IP interna del gateway de C2 (destino)
C2_GW_HOST     = "C2-GW-DELTA"      # asset cyber común para asset_convergence
C2_NET_EW      = "C2-NET-DELTA"     # affected_system EW común
LEGIT_USER     = "op.delta7"        # cuenta operativa comprometida

# Sensor EW desplegado en la AO (Pirineo aragonés, ficticio)
AO_SENSOR_LAT  = 42.5000
AO_SENSOR_LON  = 0.8000


# ============================================================================
# Constructores — cadena de ataque
# ============================================================================

def build_attack_cyber(t0: datetime) -> list[RawCyberEvent]:
    """4 eventos cyber del ataque: T1595 → T1071 → T1499 → T1565."""

    e2 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=1),
        "event": {
            "kind": "alert", "category": ["network", "intrusion_detection"],
            "module": "ids", "severity": 4,
        },
        "source":      {"ip": ATTACKER_IP, "port": 49221},
        "destination": {"ip": C2_GATEWAY_IP, "port": 443},
        "host":        {"name": C2_GW_HOST},
        "rule": {"id": "NET-RECON-21",
                 "name": "Aggressive port and service scan against perimeter gateway"},
        "message": (
            "Aggressive multi-port reconnaissance scan against the public-facing "
            f"interface of {C2_GW_HOST} (10.40.50.10) from external IP {ATTACKER_IP}. "
        ),
    })

    e4 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=5),
        "event": {
            "kind": "alert", "category": ["network", "intrusion_detection"],
            "module": "ndr", "severity": 4,
        },
        "source":      {"ip": ATTACKER_IP, "port": 53},
        "destination": {"ip": C2_GATEWAY_IP, "port": 53},
        "host":        {"name": C2_GW_HOST},
        "dns":         {"question": {"name": "exf.q1a8b3.adversary-c2.net"}},
        "rule": {"id": "DNS-EXFIL-44",
                 "name": "Suspected DNS tunneling — high-entropy subdomain pattern"},
        "message": (
            "Unusual outbound DNS traffic pattern observed from internal segment of "
            f"{C2_GW_HOST}: long sequence of high-entropy subdomain queries to the "
            "domain adversary-c2.net with TXT record responses encoding command "
            "payloads."
        ),
    })

    e6 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=10),
        "event": {
            "kind": "alert", "category": ["network", "intrusion_detection"],
            "module": "edr", "severity": 5,
        },
        "source":      {"ip": ATTACKER_IP, "port": 0},
        "destination": {"ip": C2_GATEWAY_IP, "port": 443},
        "host":        {"name": C2_GW_HOST},
        "rule": {"id": "DOS-VOLUME-12",
                 "name": "Volumetric denial-of-service against C2 backhaul service"},
        "message": (
            f"The C2 ingestion service running on {C2_GW_HOST} became unavailable due to "
            "sustained application-layer request flooding against the service endpoint on "
            "port 443. The process reached connection and worker-thread limits, causing "
            "request timeouts and service availability below 30%."
        ),
    })

    e8 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=14),
        "event": {
            "kind": "alert", "category": ["database", "intrusion_detection"],
            "module": "database_audit", "severity": 5,
        },
        "host":        {"name": C2_GW_HOST},
        "user":        {"name": LEGIT_USER},
        "destination": {"ip": C2_GATEWAY_IP, "port": 5432},
        "rule": {"id": "DB-INT-77",
                 "name": "Unauthorized modification of unit tracking records"},
        "message": (
            f"User {LEGIT_USER} executed unauthorized UPDATE statements against the "
            "unit_tracking table on the C2 dashboard backend. Existing position, heading "
            "and timestamp records for UCT-DELTA-7 were overwritten. "
        ),
    })

    return [e2, e4, e6, e8]


def build_attack_ew(t0: datetime) -> list[RawEwEvent]:
    """4 eventos EW del ataque: TEW01 → TEW07 → TEW11 → TEW06.2."""

    sensor = EwSensorInfo(
        id="EW-SENSOR-AO-01", type="SDR",
        lat=AO_SENSOR_LAT, lon=AO_SENSOR_LON,
    )

    e1 = RawEwEvent(
        id="EW-2026-06-21-001",
        timestamp=t0 + timedelta(minutes=0),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=1575.42,    # GNSS L1 C/A
            bw_mhz=2.0,
            power_dbm=-118.0,    # nivel ambiente, recepción pasiva
            duration_s=180.0,
            doa_deg=85.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "passive_emission",
            "severity": "low",
            "affected_system": C2_NET_EW,
            "summary": (
                "Passive RF emission detected in the GNSS L1 C/A band (1575.42 MHz) "
                "The activity is associated with an adversary SDR platform "
                "collecting baseline GNSS reception conditions before active interference. "
            ),
        }),
    )

    e3 = RawEwEvent(
        id="EW-2026-06-21-002",
        timestamp=t0 + timedelta(minutes=3),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=1575.42,
            bw_mhz=20.0,         # barrage muy ancho
            power_dbm=-55.0,     # >60 dB sobre la potencia GNSS nominal
            duration_s=240.0,
            doa_deg=85.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "intentional_interference",
            "severity": "high",
            "affected_system": C2_NET_EW,
            "summary": (
                "High-power broadband interference centred on GNSS L1 (1575.42 MHz) "
                "with 20 MHz of bandwidth and effective power 60+ dB above nominal "
                "satellite reception. Forward unit UCT-DELTA-7 GPS receivers are "
                "experiencing total loss of position fix."
            ),
        }),
    )

    e5 = RawEwEvent(
        id="EW-2026-06-21-003",
        timestamp=t0 + timedelta(minutes=7),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=1575.42,
            bw_mhz=2.0,
            power_dbm=-115.0,    # justo por encima del piso GNSS
            duration_s=300.0,
            doa_deg=85.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "spoofing",
            "severity": "critical",
            "affected_system": C2_NET_EW,
            "summary": (
                "Coherent counterfeit GNSS L1 signal detected over the AO. The signal "
                "carries valid CRC and plausible pseudoranges but the navigation "
                "message timing is offset from the visible satellite constellation, "
                "suggesting deliberate replay of previously recorded GPS signals with "
                "a controlled delay."
            ),
        }),
    )

    e7 = RawEwEvent(
        id="EW-2026-06-21-004",
        timestamp=t0 + timedelta(minutes=12),
        sensor=sensor,
        signal=EwSignalInfo(
            freq_mhz=3500.0,     # 5G NR n78
            bw_mhz=100.0,
            power_dbm=-48.0,
            duration_s=360.0,
            doa_deg=90.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "intentional_interference",
            "severity": "high",
            "affected_system": C2_NET_EW,
            "summary": (
                "Broadband interference centered on the 5G NR n78 band around 3.5 GHz was "
                "detected with approximately 100 MHz bandwidth. The signal raises the noise "
                "floor across the entire allocated 5G channel used by UCT-DELTA-7 for C2 "
                "backhaul. "
            ),
        }),
    )

    return [e1, e3, e5, e7]


# ============================================================================
# Constructores — eventos ruido
# ============================================================================

def build_noise_cyber(t0: datetime) -> list[RawCyberEvent]:
    """3 cyber sin relación con la operación: phishing histórico, DNS tunneling
    en otra infra, brute force VPN posterior."""

    n1 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=-180),  # 3h antes
        "event": {
            "kind": "alert", "category": ["email", "threat"],
            "module": "email_gateway", "severity": 3,
        },
        "source":      {"ip": "172.58.92.11"},
        "destination": {"ip": "10.10.5.45"},
        "host":        {"name": "HR-LAPTOP-23"},
        "user":        {"name": "m.fernandez"},
        "rule": {"id": "EMAIL-PHISH-08",
                 "name": "Suspected phishing — attachment with macro"},
        "message": (
            "Email gateway flagged a message to m.fernandez containing a macro-enabled "
            "Office attachment with known malicious template. Recipient is in the HR "
            "department, unrelated to operational units."
        ),
    })

    n3 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=6), 
        "event": {
            "kind": "alert", "category": ["network"],
            "module": "dns_monitor", "severity": 2,
        },
        "source":      {"ip": "10.30.7.140"},
        "destination": {"ip": "8.8.8.8", "port": 53},
        "host":        {"name": "MAIL-SRV-04"},
        "dns":         {"question": {"name": "stats.mailservice.example.org"}},
        "rule": {"id": "DNS-VOLUME-11",
                 "name": "High DNS query volume — possible misconfigured client"},
        "message": (
            "MAIL-SRV-04 generated periodic DNS tunneling traffic to mail-sync-control.net. "
            "The queries contain encoded command responses over DNS TXT records, consistent "
            "with an application-layer command-and-control channel."
            ),
        })

    n5 = RawCyberEvent.model_validate({
        "@timestamp": t0 + timedelta(minutes=18),
        "event": {
            "kind": "alert", "category": ["authentication", "iam"],
            "module": "vpn_gateway", "severity": 3,
        },
        "source":      {"ip": "203.0.113.55"},
        "destination": {"ip": "10.0.0.1"},
        "host":        {"name": "VPN-GW-CORP"},
        "user":        {"name": "guest_user_42"},
        "rule": {"id": "VPN-BF-09",
                 "name": "Repeated failed authentication on corporate VPN"},
        "message": (
            "VPN-GW-CORP recorded 47 failed authentication attempts in 4 minutes "
            "from external IP 203.0.113.55 against legacy guest accounts. No "
            "successful login."
        ),
    })

    return [n1, n3, n5]


def build_noise_ew(t0: datetime) -> list[RawEwEvent]:
    """3 EW sin relación: escucha ISM lejos, WiFi base camp, threat warning costa."""

    n2 = RawEwEvent(
        id="EW-2026-06-21-N02",
        timestamp=t0 + timedelta(minutes=-90),
        sensor=EwSensorInfo(
            id="EW-SENSOR-N-BORDER",
            type="SDR",
            lat=42.95, lon=0.80,   # 50 km al norte de la AO
        ),
        signal=EwSignalInfo(
            freq_mhz=2437.0,        # WiFi ISM ch6
            bw_mhz=22.0,
            power_dbm=-72.0,
            duration_s=45.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "passive_emission",
            "severity": "low",
            "affected_system": "ISM-MONITOR-N",
            "summary": (
                "Passive WiFi traffic detected on ISM band 2.437 GHz from civilian "
                "vehicles on the access road to the northern border crossing. Routine "
                "baseline observation by the border monitoring detachment."
            ),
        }),
    )

    n4 = RawEwEvent(
        id="EW-2026-06-21-N04",
        timestamp=t0 + timedelta(minutes=9),
        sensor=EwSensorInfo(
            id="EW-SENSOR-BASE-CAMP",
            type="SDR",
            lat=42.45, lon=1.20,   # ~30 km al este de la AO
        ),
        signal=EwSignalInfo(
            freq_mhz=2462.0,
            bw_mhz=20.0,
            power_dbm=-65.0,
            duration_s=120.0,
        ),
        detection=EwDetectionInfo.model_validate({
            "class": "passive_emission",
            "severity": "low",
            "affected_system": "BASE-CAMP-WIFI",
            "summary": (
                "Passive RF monitoring detected WiFi activity at base camp on ISM channel 11. "
                "The observation corresponds to local electromagnetic recon/baseline "
                "collection of a contractor hotspot"
            ),
        }),
    )

    return [n2, n4]


# ============================================================================
# Utilidades de visualización
# ============================================================================

def banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


def print_event_classification(idx, label, classified, elapsed):
    techs = ", ".join(
        f"{t.technique_id}[{t.tactic}]" for t in classified.techniques
    ) or "(none)"
    print(f"  [{idx:>2}] {label}  →  {techs}    ({elapsed:.1f}s)")
    print(f"       asset={classified.asset_id}  artifacts={classified.artifacts}")


def print_chain_summary(chain, role: str = "?") -> None:
    print(f"\n  [{role}] Chain {chain.chain_id[:8]}:  "
          f"{chain.event_count} events  ·  "
          f"{chain.pair_count} pairs  ·  "
          f"strength {chain.total_strength:.3f}")
    print(f"    duration {int(chain.duration_s)}s  "
          f"domains {' + '.join(sorted(chain.domains))}  "
          f"cross-dom {chain.is_cross_domain}")
    by_method = {}
    for c in chain.correlations:
        by_method[c.method] = by_method.get(c.method, 0) + 1
    if by_method:
        breakdown = "  ".join(f"{m}×{n}" for m, n in sorted(by_method.items()))
        print(f"    rules: {breakdown}")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()

    # Cargamos la config y forzamos el path del DB a este escenario.
    with CONFIG.open("r", encoding="utf-8") as f:
        config_dict = json.load(f)
    config_dict["paths"]["db"] = str(DB_PATH)

    banner("STEP 0 — Initialize pipeline (DB: scenario_gnss_5g.db)")
    pipeline = Pipeline(config_dict, base_path=CONFIG.parent)
    print("  Pipeline ready.")

    # Anclamos la operación a 'ahora -20min'
    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)

    attack_cyber = build_attack_cyber(t0)
    attack_ew    = build_attack_ew(t0)
    noise_cyber  = build_noise_cyber(t0)
    noise_ew     = build_noise_ew(t0)

    # Etiquetamos por categoría para identificación posterior
    tagged: list[tuple[str, str, object]] = (
        [("attack", "cyber", e) for e in attack_cyber]
      + [("attack", "ew",    e) for e in attack_ew]
      + [("noise",  "cyber", e) for e in noise_cyber]
      + [("noise",  "ew",    e) for e in noise_ew]
    )
    # Procesamos en orden cronológico
    tagged.sort(key=lambda x: x[2].timestamp)

    banner(f"STEP 1 — Classification + correlation ({len(tagged)} events)")
    print(f"  Attack: {len(attack_cyber)} cyber + {len(attack_ew)} EW")
    print(f"  Noise:  {len(noise_cyber)} cyber + {len(noise_ew)} EW")
    print()

    # Mapa raw_event_id_python_obj → (category, classified_event_id_uuid)
    # para escribir el sidecar al final.
    attack_ids: list[str] = []
    noise_ids:  list[str] = []

    for idx, (category, domain, raw_ev) in enumerate(tagged, start=1):
        offset_min = (raw_ev.timestamp - t0).total_seconds() / 60
        tag = f"{category:<6} {domain:<5} T{offset_min:+5.0f}min"
        start = time.monotonic()
        try:
            if domain == "cyber":
                classified, new_corrs = pipeline.process_cyber(raw_ev)
            else:
                classified, new_corrs = pipeline.process_ew(raw_ev)
            elapsed = time.monotonic() - start
            print_event_classification(idx, tag, classified, elapsed)
            if new_corrs:
                methods = ", ".join(sorted({c.method for c in new_corrs}))
                print(f"       ⇢ {len(new_corrs)} new correlation(s): {methods}")
            if category == "attack":
                attack_ids.append(str(classified.event_id))
            else:
                noise_ids.append(str(classified.event_id))
        except Exception as e:
            elapsed = time.monotonic() - start
            print(f"  [{idx}] {tag}  →  FAILED: {type(e).__name__}: {e}  ({elapsed:.1f}s)")
            print("\n  Aborting due to classification failure.")
            return

    stats = pipeline.storage.stats()
    print(f"\n  BD state: {stats['events_total']} events, "
          f"{stats['correlations_total']} correlations stored")

    # ===============================================  STEP 2 — chain extraction
    banner("STEP 2 — Chain extraction (umbral 0.0, sin filtro)")
    chains = pipeline.chain_extractor.extract(
        min_pair_strength=0.0, min_events=2,
    )
    print(f"  {len(chains)} chain(s) detected")
    if not chains:
        print("  No chains detected — something is off.")
        _write_sidecar(attack_ids, noise_ids)
        return

    chains.sort(key=lambda c: -c.total_strength)

    # Identificamos la cadena del ataque: la que tiene más solapamiento con
    # los attack_ids. Las otras cadenas son ruido/incidentales.
    attack_id_set = set(attack_ids)
    chain_scores = []
    for ch in chains:
        ch_event_ids = {str(ev.event_id) for ev in ch.events}
        overlap = len(ch_event_ids & attack_id_set)
        chain_scores.append((overlap, ch))
    chain_scores.sort(key=lambda x: (-x[0], -x[1].total_strength))
    attack_chain = chain_scores[0][1] if chain_scores[0][0] > 0 else None
    other_chains = [ch for ovl, ch in chain_scores if ch is not attack_chain]

    if attack_chain is not None:
        print_chain_summary(attack_chain, role="ATTACK")
    else:
        print("  WARN: no chain contains attack events. Check correlations.")
    for ch in other_chains:
        print_chain_summary(ch, role="other")

    # ===============================================  STEP 3 — separation
    banner("STEP 3 — Separación ataque vs ruido")
    if attack_chain is None:
        print("  No attack chain identified — skipped.")
    else:
        attack_in_chain = sum(
            1 for ev in attack_chain.events if str(ev.event_id) in attack_id_set
        )
        noise_in_chain  = sum(
            1 for ev in attack_chain.events if str(ev.event_id) in set(noise_ids)
        )
        connectivity = attack_in_chain / len(attack_ids) if attack_ids else 0.0
        max_other = max((ch.total_strength for ch in other_chains), default=0.0)
        sep_ratio = (
            attack_chain.total_strength / max_other if max_other > 0 else float("inf")
        )
        print(f"  attack chain total_strength : {attack_chain.total_strength:.3f}")
        print(f"  attack events in chain      : {attack_in_chain}/{len(attack_ids)}  "
              f"(connectivity {connectivity*100:.0f}%)")
        print(f"  noise events absorbed       : {noise_in_chain}/{len(noise_ids)}")
        print(f"  strongest other chain       : {max_other:.3f}")
        print(f"  separation ratio            : "
              f"{'∞' if sep_ratio == float('inf') else f'{sep_ratio:.2f}'}×")

    # ===============================================  STEP 4 — checklist
    banner("STEP 4 — Verification checklist")
    checks = [
        ("All 13 raw events classified",
         (len(attack_ids) + len(noise_ids)) == 13),
        ("Attack chain extracted",
         attack_chain is not None),
        ("Attack chain is cross-domain",
         attack_chain is not None and attack_chain.is_cross_domain),
        ("All 8 attack events in attack chain",
         attack_chain is not None and
         sum(1 for ev in attack_chain.events if str(ev.event_id) in attack_id_set) == 8),
        ("≤1 noise event absorbed (umbral 0)",
         attack_chain is not None and
         sum(1 for ev in attack_chain.events if str(ev.event_id) in set(noise_ids)) <= 1),
    ]
    for label, ok in checks:
        print(f"  [{'✓' if ok else '✗'}] {label}")

    # ===============================================  STEP 5 — sidecar
    _write_sidecar(attack_ids, noise_ids)
    print(f"\n  Sidecar written: {SIDECAR_PATH.name}")
    print(
        "\n  Next: run validation_sensitivity.py to test parameter sensitivity\n"
        "        against this scenario alongside MMSI.\n"
    )


def _write_sidecar(attack_ids: list[str], noise_ids: list[str]) -> None:
    """Sidecar JSON que la sensibilidad lee para distinguir ataque de ruido."""
    SIDECAR_PATH.write_text(
        json.dumps({
            "scenario": "gnss_5g_denial",
            "db": str(DB_PATH.name),
            "attack_event_ids": attack_ids,
            "noise_event_ids": noise_ids,
        }, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
