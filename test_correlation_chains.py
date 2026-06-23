"""Pruebas sintéticas de cadenas de ataque sobre el motor de correlación.

Este script NO llama al LLM. Construye eventos `ClassifiedEvent` ya clasificados
con técnicas MITRE/EW y comprueba dos niveles:

1. Correlación por pares: cada regla genera aristas entre eventos.
2. Cadena/grafo: las aristas guardadas permiten reconstruir caminos de 5-8
   eventos en escenarios ciber-EW y ciber-only.

Uso:
    python test_correlation_chains.py

Colócalo en la raíz del proyecto de correlación, junto a:
    engine.py, rules.py, schemas.py, storage.py, knowledge/

o ejecútalo desde una carpeta que contenga ./correlation_review.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

# -----------------------------------------------------------------------------
# Resolución de paths: funciona dentro de la raíz del proyecto o desde /mnt/data
# con ./correlation_review.
# -----------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
if (HERE / "engine.py").exists():
    PROJECT_DIR = HERE
elif (HERE / "correlation_review" / "engine.py").exists():
    PROJECT_DIR = HERE / "correlation_review"
else:
    raise RuntimeError(
        "No encuentro engine.py. Copia este archivo a la raíz del proyecto "
        "o ejecútalo desde una carpeta que contenga ./correlation_review."
    )

sys.path.insert(0, str(PROJECT_DIR))

from engine import CorrelationEngine  # noqa: E402
from rules import (  # noqa: E402
    AssetConvergenceRule,
    CrossDomainMappingRule,
    GeographicProximityRule,
    KillChainRule,
    SharedArtifactRule,
)
from schemas import ClassifiedEvent, TechniqueAssignment  # noqa: E402
from storage import CorrelationStore  # noqa: E402

KNOWLEDGE = PROJECT_DIR / "knowledge"
DB_DIR = PROJECT_DIR


# -----------------------------------------------------------------------------
# Configuración del motor
# -----------------------------------------------------------------------------

def make_engine(store: CorrelationStore) -> CorrelationEngine:
    rules = [
        KillChainRule(
            tactics_order_path=KNOWLEDGE / "tactics_order.json",
            window_seconds=1800,       # 30 min
        ),
        CrossDomainMappingRule(
            mapping_path=KNOWLEDGE / "ew_mitre_mapping.json",
            window_seconds=3600,       # 1 h
        ),
        AssetConvergenceRule(
            window_seconds=600,        # 10 min
        ),
        GeographicProximityRule(
            max_distance_m=5000,
            tau_d_m=1000,
            window_seconds=600,        # 10 min
        ),
        SharedArtifactRule(
            window_seconds=7200,       # 2 h
        ),
    ]

    # Deben coincidir con los métodos definidos por las reglas.
    rule_weights = {
        "kill_chain": 0.30,
        "cross_domain": 0.20,
        "asset_convergence": 0.10,
        "geo_proximity": 0.10,
        "shared_artifact": 0.30,
    }

    return CorrelationEngine(
        storage=store,
        rules=rules,
        rule_weights=rule_weights,
        global_tau_t=300.0,
    )


# -----------------------------------------------------------------------------
# Helpers de eventos sintéticos
# -----------------------------------------------------------------------------

def make_event(
    *,
    label: str,
    domain: str,
    timestamp: datetime,
    techniques: list[tuple[str, str, str, float]],
    asset_id: str | None = None,
    user_id: str | None = None,
    location: tuple[float, float] | None = None,
    artifacts: list[str] | None = None,
) -> ClassifiedEvent:
    """Crea un ClassifiedEvent ya clasificado.

    techniques: [(technique_id, technique_name, tactic, confidence), ...]
    """
    return ClassifiedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        domain=domain,  # type: ignore[arg-type]
        techniques=[
            TechniqueAssignment(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                confidence=conf,
                reasoning="Synthetic classified event for chain-correlation testing.",
            )
            for tid, name, tactic, conf in techniques
        ],
        asset_id=asset_id,
        user_id=user_id,
        location=location,
        artifacts=artifacts or [],
        classifier_model="synthetic",
        raw={"label": label, "source": "synthetic-chain-test"},
    )


def label_of(event: ClassifiedEvent) -> str:
    return str(event.raw.get("label", event.event_id))


def compact_methods(methods: set[str]) -> str:
    return ", ".join(sorted(methods)) if methods else "-"


def compact_metadata(meta: dict) -> str:
    if not meta:
        return "{}"
    priority = [
        "from_technique", "to_technique", "ew_technique", "mitre_technique",
        "asset_id", "best_artifact", "distance_m", "tier_distance",
    ]
    parts: list[str] = []
    for key in priority:
        if key in meta:
            parts.append(f"{key}={meta[key]}")
    if not parts:
        for key, value in list(meta.items())[:3]:
            parts.append(f"{key}={value}")
    return "{" + ", ".join(parts) + "}"


# -----------------------------------------------------------------------------
# Escenarios de 5-8 eventos
# -----------------------------------------------------------------------------

@dataclass
class Scenario:
    name: str
    description: str
    events: list[ClassifiedEvent]
    expected_path_labels: list[str]
    expected_edge_methods: dict[tuple[str, str], set[str]]
    noise_labels_without_correlations: list[str]
    expect_zero_correlations: bool = False


def scenario_gnss_cema() -> Scenario:
    """8 eventos: 7 forman cadena ciber-EW + 1 ruido sin técnicas."""
    t0 = datetime(2026, 6, 20, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            label="A1_CY_RECON_NAV",
            domain="cyber",
            timestamp=t0,
            techniques=[("T1595", "Active Scanning", "reconnaissance", 0.86)],
            asset_id="NAV-CTRL-UAV-01",
            artifacts=["ip:203.0.113.10"],
        ),
        make_event(
            label="A2_EW_RECON_GNSS",
            domain="ew",
            timestamp=t0 + timedelta(minutes=1),
            techniques=[("TEW01", "Electromagnetic Reconnaissance", "detect", 0.88)],
            asset_id="GPS-RX-UAV-01",
            location=(40.4168, -3.7038),
        ),
        make_event(
            label="A3_EW_PROBING_GNSS",
            domain="ew",
            timestamp=t0 + timedelta(minutes=3),
            techniques=[("TEW04", "Electromagnetic Probing", "exploit", 0.84)],
            asset_id="GPS-RX-UAV-01",
            location=(40.4171, -3.7040),
        ),
        make_event(
            label="A4_CY_INITIAL_ACCESS_NAV",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=5),
            techniques=[("T1190", "Exploit Public-Facing Application", "initial-access", 0.83)],
            asset_id="NAV-CTRL-UAV-01",
            artifacts=["ip:185.220.101.42", "domain:c2-uav.example"],
        ),
        make_event(
            label="A5_CY_C2_NAV",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=7),
            techniques=[("T1071", "Application Layer Protocol", "command-and-control", 0.91)],
            asset_id="NAV-CTRL-UAV-01",
            artifacts=["ip:185.220.101.42", "domain:c2-uav.example"],
        ),
        make_event(
            label="A6_CY_DOS_NAV",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=9),
            techniques=[("T1498", "Network Denial of Service", "impact", 0.81)],
            asset_id="NAV-CTRL-UAV-01",
            artifacts=["ip:185.220.101.42", "domain:c2-uav.example"],
        ),
        make_event(
            label="A7_EW_JAMMING_GNSS",
            domain="ew",
            timestamp=t0 + timedelta(minutes=12),
            techniques=[("TEW06.2", "Barrage Jamming", "degrade-disrupt", 0.93)],
            asset_id="GPS-RX-UAV-01",
            location=(40.4170, -3.7036),
        ),
        make_event(
            label="A8_NOISE_EMPTY",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=13),
            techniques=[],
            asset_id="WS-NOISE-01",
            artifacts=["ip:198.51.100.77"],
        ),
    ]
    path = [
        "A1_CY_RECON_NAV",
        "A2_EW_RECON_GNSS",
        "A3_EW_PROBING_GNSS",
        "A4_CY_INITIAL_ACCESS_NAV",
        "A5_CY_C2_NAV",
        "A6_CY_DOS_NAV",
        "A7_EW_JAMMING_GNSS",
    ]
    edge_methods = {
        ("A1_CY_RECON_NAV", "A2_EW_RECON_GNSS"): {"kill_chain", "cross_domain"},
        ("A2_EW_RECON_GNSS", "A3_EW_PROBING_GNSS"): {"kill_chain", "asset_convergence", "geo_proximity"},
        ("A3_EW_PROBING_GNSS", "A4_CY_INITIAL_ACCESS_NAV"): {"kill_chain", "cross_domain"},
        ("A4_CY_INITIAL_ACCESS_NAV", "A5_CY_C2_NAV"): {"kill_chain", "asset_convergence", "shared_artifact"},
        ("A5_CY_C2_NAV", "A6_CY_DOS_NAV"): {"kill_chain", "asset_convergence", "shared_artifact"},
        ("A6_CY_DOS_NAV", "A7_EW_JAMMING_GNSS"): {"kill_chain", "cross_domain"},
    }
    return Scenario(
        name="GNSS_CEMA_CHAIN_8_EVENTS",
        description="Recon ciber + recon/probing EW + acceso/C2/DoS ciber + jamming GNSS + ruido.",
        events=events,
        expected_path_labels=path,
        expected_edge_methods=edge_methods,
        noise_labels_without_correlations=["A8_NOISE_EMPTY"],
    )


def scenario_adsb_deception() -> Scenario:
    """7 eventos: 6 forman cadena de decepción ADS-B + 1 ruido temporal lejano."""
    t0 = datetime(2026, 6, 20, 11, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            label="B1_CY_SCAN_SURV",
            domain="cyber",
            timestamp=t0,
            techniques=[("T1595", "Active Scanning", "reconnaissance", 0.83)],
            asset_id="SURV-APP-01",
            artifacts=["ip:203.0.113.80"],
        ),
        make_event(
            label="B2_EW_RECON_ADSB",
            domain="ew",
            timestamp=t0 + timedelta(minutes=1),
            techniques=[("TEW01", "Electromagnetic Reconnaissance", "detect", 0.87)],
            asset_id="ADSB-RX-01",
            location=(40.4920, -3.5660),
        ),
        make_event(
            label="B3_EW_DF_ADSB",
            domain="ew",
            timestamp=t0 + timedelta(minutes=3),
            techniques=[("TEW03", "Direction Finding", "exploit", 0.82)],
            asset_id="ADSB-RX-01",
            location=(40.4930, -3.5655),
        ),
        make_event(
            label="B4_CY_SNIFFING_SURV",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=5),
            techniques=[("T1040", "Network Sniffing", "discovery", 0.80)],
            asset_id="SURV-APP-01",
            artifacts=["ip:10.10.20.5", "domain:adsb-gateway.local"],
        ),
        make_event(
            label="B5_EW_INTRUSION_ADSB",
            domain="ew",
            timestamp=t0 + timedelta(minutes=7),
            techniques=[("TEW09", "Electromagnetic Intrusion", "deceive", 0.86)],
            asset_id="ADSB-RX-01",
            location=(40.4925, -3.5662),
        ),
        make_event(
            label="B6_CY_DATA_MANIP_SURV",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=9),
            techniques=[("T1565", "Data Manipulation", "impact", 0.84)],
            asset_id="SURV-APP-01",
            artifacts=["domain:adsb-gateway.local"],
        ),
        make_event(
            label="B7_NOISE_FAR_EW",
            domain="ew",
            timestamp=t0 + timedelta(hours=3, minutes=30),
            techniques=[("TEW08.1", "Simulative Deception", "deceive", 0.80)],
            asset_id="WEATHER-RADAR-99",
            location=(41.3874, 2.1686),
        ),
    ]
    path = [
        "B1_CY_SCAN_SURV",
        "B2_EW_RECON_ADSB",
        "B3_EW_DF_ADSB",
        "B4_CY_SNIFFING_SURV",
        "B5_EW_INTRUSION_ADSB",
        "B6_CY_DATA_MANIP_SURV",
    ]
    edge_methods = {
        ("B1_CY_SCAN_SURV", "B2_EW_RECON_ADSB"): {"kill_chain", "cross_domain"},
        ("B2_EW_RECON_ADSB", "B3_EW_DF_ADSB"): {"kill_chain", "asset_convergence", "geo_proximity"},
        ("B3_EW_DF_ADSB", "B4_CY_SNIFFING_SURV"): {"kill_chain", "cross_domain"},
        ("B4_CY_SNIFFING_SURV", "B5_EW_INTRUSION_ADSB"): {"kill_chain", "cross_domain"},
        ("B5_EW_INTRUSION_ADSB", "B6_CY_DATA_MANIP_SURV"): {"kill_chain", "cross_domain"},
    }
    return Scenario(
        name="ADSB_DECEPTION_CHAIN_7_EVENTS",
        description="Recon/DF EW + sniffing ciber + intrusion/deception EW + manipulación de datos ADS-B.",
        events=events,
        expected_path_labels=path,
        expected_edge_methods=edge_methods,
        noise_labels_without_correlations=["B7_NOISE_FAR_EW"],
    )


def scenario_cyber_only_chain() -> Scenario:
    """5 eventos: cadena ciber pura para comprobar que no todo depende de EW."""
    t0 = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            label="C1_PHISHING",
            domain="cyber",
            timestamp=t0,
            techniques=[("T1566", "Phishing", "initial-access", 0.84)],
            asset_id="WS-042",
            user_id="operator.alpha",
            artifacts=["domain:invoice-update.example", "user:operator.alpha"],
        ),
        make_event(
            label="C2_USER_EXECUTION",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=2),
            techniques=[("T1204", "User Execution", "execution", 0.82)],
            asset_id="WS-042",
            user_id="operator.alpha",
            artifacts=["hash:aaaabbbbcccc1111", "user:operator.alpha"],
        ),
        make_event(
            label="C3_COMMAND_SHELL",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=4),
            techniques=[("T1059", "Command and Scripting Interpreter", "execution", 0.88)],
            asset_id="WS-042",
            user_id="operator.alpha",
            artifacts=["hash:aaaabbbbcccc1111", "domain:c2-chain.example"],
        ),
        make_event(
            label="C4_C2_CHANNEL",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=7),
            techniques=[("T1071", "Application Layer Protocol", "command-and-control", 0.91)],
            asset_id="WS-042",
            artifacts=["domain:c2-chain.example", "ip:185.220.101.99"],
        ),
        make_event(
            label="C5_EXFILTRATION",
            domain="cyber",
            timestamp=t0 + timedelta(minutes=10),
            techniques=[("T1041", "Exfiltration Over C2 Channel", "exfiltration", 0.86)],
            asset_id="WS-042",
            artifacts=["domain:c2-chain.example", "ip:185.220.101.99"],
        ),
    ]
    path = [
        "C1_PHISHING",
        "C2_USER_EXECUTION",
        "C3_COMMAND_SHELL",
        "C4_C2_CHANNEL",
        "C5_EXFILTRATION",
    ]
    edge_methods = {
        ("C1_PHISHING", "C2_USER_EXECUTION"): {"kill_chain", "asset_convergence"},
        ("C2_USER_EXECUTION", "C3_COMMAND_SHELL"): {"kill_chain", "asset_convergence", "shared_artifact"},
        ("C3_COMMAND_SHELL", "C4_C2_CHANNEL"): {"kill_chain", "asset_convergence", "shared_artifact"},
        ("C4_C2_CHANNEL", "C5_EXFILTRATION"): {"kill_chain", "asset_convergence", "shared_artifact"},
    }
    return Scenario(
        name="CYBER_ONLY_CHAIN_5_EVENTS",
        description="Phishing → ejecución → shell → C2 → exfiltración.",
        events=events,
        expected_path_labels=path,
        expected_edge_methods=edge_methods,
        noise_labels_without_correlations=[],
    )


def scenario_negative_noise() -> Scenario:
    """6 eventos de ruido espaciados >2h: no debería haber correlaciones."""
    t0 = datetime(2026, 6, 20, 13, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(
            label="D1_NOISE_CY_IMPACT",
            domain="cyber",
            timestamp=t0,
            techniques=[("T1489", "Service Stop", "impact", 0.80)],
            asset_id="MAIL-01",
            artifacts=["ip:192.0.2.10"],
        ),
        make_event(
            label="D2_NOISE_EW_DETECT_FAR_TIME",
            domain="ew",
            timestamp=t0 + timedelta(hours=3),
            techniques=[("TEW01", "Electromagnetic Reconnaissance", "detect", 0.80)],
            asset_id="RADAR-77",
            location=(43.2630, -2.9350),
        ),
        make_event(
            label="D3_NOISE_CY_RECON_FAR_TIME",
            domain="cyber",
            timestamp=t0 + timedelta(hours=6),
            techniques=[("T1595", "Active Scanning", "reconnaissance", 0.80)],
            asset_id="WEB-TEST-99",
            artifacts=["ip:198.51.100.201"],
        ),
        make_event(
            label="D4_NOISE_EW_JAM_FAR_TIME",
            domain="ew",
            timestamp=t0 + timedelta(hours=9),
            techniques=[("TEW06.1", "Spot Jamming", "degrade-disrupt", 0.80)],
            asset_id="VHF-LINK-22",
            location=(36.7213, -4.4214),
        ),
        make_event(
            label="D5_NOISE_EMPTY",
            domain="cyber",
            timestamp=t0 + timedelta(hours=12),
            techniques=[],
            asset_id="WS-EMPTY-01",
            artifacts=["domain:benign.example"],
        ),
        make_event(
            label="D6_NOISE_CY_COLLECTION_FAR_TIME",
            domain="cyber",
            timestamp=t0 + timedelta(hours=15),
            techniques=[("T1005", "Data from Local System", "collection", 0.80)],
            asset_id="LAPTOP-123",
            artifacts=["hash:ffffffffeeee1111"],
        ),
    ]
    return Scenario(
        name="NEGATIVE_NOISE_6_EVENTS",
        description="Eventos intencionadamente inconexos y fuera de ventana; no debería generarse ninguna correlación.",
        events=events,
        expected_path_labels=[],
        expected_edge_methods={},
        noise_labels_without_correlations=[label_of(e) for e in events],
        expect_zero_correlations=True,
    )


# -----------------------------------------------------------------------------
# Validación y grafo de caminos
# -----------------------------------------------------------------------------

@dataclass
class PairRow:
    a: ClassifiedEvent
    b: ClassifiedEvent
    methods: set[str]
    strength: float


def collect_pair_rows(
    store: CorrelationStore,
    engine: CorrelationEngine,
    events: list[ClassifiedEvent],
) -> list[PairRow]:
    rows: list[PairRow] = []
    for i, a in enumerate(events):
        for b in events[i + 1:]:
            corrs = store.get_correlations_for_pair(a.event_id, b.event_id)
            if not corrs:
                continue
            strength = engine.aggregate_pair_strength(corrs, a, b)
            rows.append(PairRow(a=a, b=b, methods={c.method for c in corrs}, strength=strength))
    rows.sort(key=lambda r: r.strength, reverse=True)
    return rows


def assert_pair_has_methods(
    store: CorrelationStore,
    a: ClassifiedEvent,
    b: ClassifiedEvent,
    expected: set[str],
) -> None:
    corrs = store.get_correlations_for_pair(a.event_id, b.event_id)
    actual = {c.method for c in corrs}
    missing = expected - actual
    if missing:
        raise AssertionError(
            f"Faltan métodos para {label_of(a)} → {label_of(b)}. "
            f"Esperados={sorted(expected)}, actuales={sorted(actual)}"
        )


def assert_event_has_no_correlations(store: CorrelationStore, event: ClassifiedEvent) -> None:
    corrs = store.get_correlations_for_event(event.event_id)
    if corrs:
        details = [(c.method, c.score, c.metadata) for c in corrs]
        raise AssertionError(
            f"{label_of(event)} no debería correlacionarse, pero tiene: {details}"
        )


def assert_expected_path(
    store: CorrelationStore,
    scenario: Scenario,
) -> None:
    by_label = {label_of(e): e for e in scenario.events}
    labels = scenario.expected_path_labels
    for a_label, b_label in zip(labels, labels[1:]):
        expected = scenario.expected_edge_methods.get((a_label, b_label), set())
        if not expected:
            raise AssertionError(f"No hay métodos esperados definidos para {a_label} → {b_label}")
        assert_pair_has_methods(store, by_label[a_label], by_label[b_label], expected)


def longest_path_from_correlations(
    rows: list[PairRow],
    min_strength: float = 0.01,
) -> tuple[list[str], float]:
    """Calcula un camino largo en el DAG temporal inducido por las correlaciones.

    No pretende ser el detector final de cadenas de ataque. Es una utilidad de
    test para comprobar que las aristas guardadas permiten reconstruir caminos
    temporales de varios eventos.
    """
    # Nodos ordenados cronológicamente.
    nodes: dict[str, ClassifiedEvent] = {}
    edges: dict[str, list[tuple[str, float]]] = {}
    for row in rows:
        if row.strength < min_strength:
            continue
        a_label = label_of(row.a)
        b_label = label_of(row.b)
        nodes[a_label] = row.a
        nodes[b_label] = row.b
        # Los eventos del motor ya son temporales: a es anterior a b en la BD.
        if row.a.timestamp <= row.b.timestamp:
            src, dst = a_label, b_label
        else:
            src, dst = b_label, a_label
        edges.setdefault(src, []).append((dst, row.strength))

    ordered = sorted(nodes, key=lambda lbl: nodes[lbl].timestamp)
    best_path: dict[str, list[str]] = {lbl: [lbl] for lbl in ordered}
    best_score: dict[str, float] = {lbl: 0.0 for lbl in ordered}

    for src in ordered:
        for dst, w in edges.get(src, []):
            candidate = best_path[src] + [dst]
            candidate_score = best_score[src] + w
            if len(candidate) > len(best_path.get(dst, [dst])) or (
                len(candidate) == len(best_path.get(dst, [dst]))
                and candidate_score > best_score.get(dst, 0.0)
            ):
                best_path[dst] = candidate
                best_score[dst] = candidate_score

    if not best_path:
        return [], 0.0
    end = max(best_path, key=lambda lbl: (len(best_path[lbl]), best_score[lbl]))
    return best_path[end], best_score[end]


def run_scenario(scenario: Scenario) -> None:
    db_path = DB_DIR / f"tfm_chain_test_{scenario.name.lower()}.db"
    if db_path.exists():
        db_path.unlink()

    store = CorrelationStore(db_path)
    engine = make_engine(store)

    print("\n" + "=" * 100)
    print(f"ESCENARIO: {scenario.name}")
    print("=" * 100)
    print(scenario.description)
    print(f"Eventos: {len(scenario.events)} | BD: {db_path}")

    print("\n1) Procesando eventos")
    print("-" * 100)
    for ev in scenario.events:
        techs = ", ".join(f"{t.technique_id}/{t.tactic}" for t in ev.techniques) or "SIN_TECNICAS"
        new_corrs = engine.process(ev)
        print(f"{label_of(ev):32s} | {ev.domain:5s} | {ev.timestamp.time()} | asset={ev.asset_id} | {techs}")
        if new_corrs:
            for c in new_corrs:
                print(
                    f"  ↳ {c.method:17s} score={c.score:.2f} "
                    f"Δt={c.delta_t_s:>6.1f}s meta={compact_metadata(c.metadata)}"
                )
        else:
            print("  ↳ sin correlaciones nuevas")

    all_corrs = store.get_all_correlations(min_score=0.0)
    if scenario.expect_zero_correlations and all_corrs:
        raise AssertionError(
            f"El escenario {scenario.name} esperaba 0 correlaciones, "
            f"pero se generaron {len(all_corrs)}."
        )

    print("\n2) Validando camino esperado")
    print("-" * 100)
    if scenario.expected_path_labels:
        assert_expected_path(store, scenario)
        print("  ✓ Camino esperado validado:")
        print("    " + "  →  ".join(scenario.expected_path_labels))
    else:
        print("  ✓ No hay camino esperado en este escenario negativo")

    print("\n3) Validando ruido")
    print("-" * 100)
    by_label = {label_of(e): e for e in scenario.events}
    if scenario.noise_labels_without_correlations:
        for noise_label in scenario.noise_labels_without_correlations:
            assert_event_has_no_correlations(store, by_label[noise_label])
            print(f"  ✓ {noise_label}: sin correlaciones")
    else:
        print("  - Sin eventos de ruido aislado en este escenario")

    print("\n4) Ranking de pares correlados")
    print("-" * 100)
    rows = collect_pair_rows(store, engine, scenario.events)
    if not rows:
        print("  No hay pares correlados")
    else:
        for row in rows[:15]:
            print(
                f"  {label_of(row.a):32s} → {label_of(row.b):32s} "
                f"strength={row.strength:.3f} methods=[{compact_methods(row.methods)}]"
            )

    path, path_score = longest_path_from_correlations(rows, min_strength=0.01)
    print("\n5) Camino más largo encontrado en el grafo de correlaciones")
    print("-" * 100)
    if path:
        print(f"  Longitud={len(path)} | score acumulado aprox={path_score:.3f}")
        print("  " + "  →  ".join(path))
    else:
        print("  No hay camino en el grafo")

    print("\n6) Estadísticas SQLite")
    print("-" * 100)
    for k, v in store.stats().items():
        print(f"  {k:25s}: {v}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main() -> None:
    scenarios = [
        scenario_gnss_cema(),
        scenario_adsb_deception(),
        scenario_cyber_only_chain(),
        scenario_negative_noise(),
    ]

    print("Proyecto:", PROJECT_DIR)
    print("Knowledge:", KNOWLEDGE)
    print("\nSe ejecutarán escenarios de 5-8 eventos con eventos ya clasificados.")

    for scenario in scenarios:
        run_scenario(scenario)

    print("\n" + "=" * 100)
    print("OK: todas las pruebas de cadenas terminaron sin errores.")
    print("=" * 100)


if __name__ == "__main__":
    main()
