"""Análisis de sensibilidad cruzada sobre los escenarios MMSI y GNSS+5G.

Recorre tres barridos paramétricos sobre dos bases de datos previamente
pobladas (MMSI y GNSS+5G de denegación), reagregando las strengths y
re-extrayendo cadenas SIN reclasificar ni reconstruir correlaciones. Esto
hace los experimentos baratos, reproducibles y desacoplados del LLM.

Barridos
--------
  1. global_tau_t      ∈ {60, 150, 300, 600, 1200, 3600} s
  2. rule_weights      5 configuraciones nombradas
  3. min_pair_strength ∈ {0.0, 0.05, 0.10, 0.15, 0.20, 0.30, 0.50}

Salida
------
  - sensitivity_results.csv             tabla larga con todos los puntos
  - sensitivity_tau_t.png               curvas total_strength vs τ_t
  - sensitivity_weights.png             barras agrupadas por configuración
  - sensitivity_threshold.png           connectivity y noise inclusion

Pre-condición
-------------
  - scenario MMSI ejecutado → tfm_system.db
  - scenario GNSS+5G ejecutado → scenario_gnss_5g.db + scenario_gnss_5g.events.json

Uso
---
  python validation_sensitivity.py
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Optional

_ROOT = Path(__file__).parent.parent  # tests/ -> repo root
sys.path.insert(0, str(_ROOT / 'src' / 'modules'))
sys.path.insert(0, str(_ROOT / 'src'))

from chains import ChainExtractor
from engine import CorrelationEngine
from pipeline import Pipeline


HERE = Path(__file__).parent.parent  # -> repo root
CONFIG = HERE / "config.json"
OUTPUT_DIR = HERE / "sensitivity_output"


# ============================================================================
# Definición de los escenarios a analizar
# ============================================================================

@dataclass
class Scenario:
    label: str
    db: Path
    sidecar: Optional[Path]
    attack_ids: set[str] = field(default_factory=set)
    noise_ids: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, label: str, db: Path, sidecar: Optional[Path]) -> "Scenario":
        s = cls(label=label, db=db, sidecar=sidecar)
        if sidecar and sidecar.exists():
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            s.attack_ids = set(data.get("attack_event_ids", []))
            s.noise_ids = set(data.get("noise_event_ids", []))
        return s

    @property
    def has_noise(self) -> bool:
        return len(self.noise_ids) > 0


SCENARIOS = [
    Scenario.load("mmsi",
                  db=HERE / "tfm_system.db",
                  sidecar=None),
    Scenario.load("gnss_5g",
                  db=HERE / "scenario_gnss_5g.db",
                  sidecar=HERE / "scenario_gnss_5g.events.json"),
]


# ============================================================================
# Parámetros de los barridos
# ============================================================================

TAU_T_VALUES = [60.0, 150.0, 300.0, 600.0, 1200.0, 3600.0]

WEIGHT_CONFIGS: dict[str, dict[str, float]] = {
    "current": {
        "kill_chain": 0.30, "cross_domain": 0.20,
        "asset_convergence": 0.10, "geo_proximity": 0.10,
        "shared_artifact": 0.30,
    },
    "uniform": {
        "kill_chain": 0.20, "cross_domain": 0.20,
        "asset_convergence": 0.20, "geo_proximity": 0.20,
        "shared_artifact": 0.20,
    },
    "topology-heavy": {
        "kill_chain": 0.35, "cross_domain": 0.10,
        "asset_convergence": 0.10, "geo_proximity": 0.10,
        "shared_artifact": 0.35,
    },
    "cross-heavy": {
        "kill_chain": 0.20, "cross_domain": 0.40,
        "asset_convergence": 0.10, "geo_proximity": 0.10,
        "shared_artifact": 0.20,
    },
    "evidence-light": {
        "kill_chain": 0.10, "cross_domain": 0.10,
        "asset_convergence": 0.30, "geo_proximity": 0.20,
        "shared_artifact": 0.30,
    },
}

THRESHOLD_VALUES = [0.0, 0.05, 0.10, 0.15, 0.20, 0.30, 0.50]

# Valores por defecto cuando se hace un barrido y los otros parámetros
# se mantienen fijos
DEFAULT_TAU_T = 300.0
DEFAULT_WEIGHTS = WEIGHT_CONFIGS["current"]
DEFAULT_THRESHOLD = 0.0


# ============================================================================
# Construcción del pipeline apuntando a un DB concreto
# ============================================================================

def load_pipeline_for_db(db_path: Path) -> Pipeline:
    """Carga config.json y override del db. La instanciación del LLM es lazy,
    así que esto NO requiere que vLLM esté accesible."""
    with CONFIG.open("r", encoding="utf-8") as f:
        config = json.load(f)
    config["paths"]["db"] = str(db_path.resolve())
    return Pipeline(config, base_path=CONFIG.parent)


def make_engine_and_extractor(
    pipeline: Pipeline,
    tau_t: float,
    rule_weights: dict[str, float],
) -> tuple[CorrelationEngine, ChainExtractor]:
    """Devuelve (engine, chain_extractor) instanciados con los parámetros dados,
    reutilizando las reglas y el storage del pipeline."""
    engine = CorrelationEngine(
        storage=pipeline.storage,
        rules=pipeline.engine.rules,
        rule_weights=rule_weights,
        global_tau_t=tau_t,
    )
    extractor = ChainExtractor(storage=pipeline.storage, engine=engine)
    return engine, extractor


# ============================================================================
# Cálculo de métricas para una extracción de cadenas concreta
# ============================================================================

@dataclass
class Metrics:
    n_chains: int = 0
    attack_chain_total_strength: float = 0.0
    attack_chain_mean_strength: float = 0.0
    attack_chain_n_events: int = 0
    attack_chain_n_pairs: int = 0
    attack_chain_is_cross_domain: bool = False
    attack_connectivity: float = 0.0       # % attack_ids dentro de la attack chain
    noise_inclusion: int = 0               # # noise_ids dentro de la attack chain
    max_other_chain_strength: float = 0.0
    separation_ratio: float = 0.0          # 0 si no hay otra cadena (infinito)


def compute_metrics(
    chains: list,
    scenario: Scenario,
) -> Metrics:
    m = Metrics(n_chains=len(chains))
    if not chains:
        return m

    # Identificación de la cadena del ataque:
    # - Si el escenario tiene atacante etiquetado, la attack chain es la que
    #   tiene mayor solapamiento con attack_ids (desempate por strength).
    # - Si no, asumimos que todos los eventos son del ataque y cogemos la más
    #   fuerte.
    if scenario.attack_ids:
        scored = []
        for ch in chains:
            ch_ids = {str(ev.event_id) for ev in ch.events}
            overlap = len(ch_ids & scenario.attack_ids)
            scored.append((overlap, ch.total_strength, ch))
        scored.sort(key=lambda x: (-x[0], -x[1]))
        if scored[0][0] == 0:
            return m  # ninguna cadena contiene eventos del ataque
        attack_chain = scored[0][2]
    else:
        attack_chain = max(chains, key=lambda c: c.total_strength)

    other_chains = [c for c in chains if c is not attack_chain]

    chain_ids = {str(ev.event_id) for ev in attack_chain.events}
    if scenario.attack_ids:
        in_chain_attack = len(chain_ids & scenario.attack_ids)
        connectivity = in_chain_attack / len(scenario.attack_ids)
        noise_inclusion = len(chain_ids & scenario.noise_ids)
    else:
        # MMSI: la attack chain debería contener "todos" los eventos del DB
        in_chain_attack = attack_chain.event_count
        connectivity = 1.0  # tautológico cuando no hay ground truth de ruido
        noise_inclusion = 0

    max_other = max((c.total_strength for c in other_chains), default=0.0)
    sep_ratio = (
        attack_chain.total_strength / max_other
        if max_other > 0 else 0.0  # 0 representa "no hay rival" (separación máxima)
    )

    m.attack_chain_total_strength = attack_chain.total_strength
    m.attack_chain_mean_strength = attack_chain.mean_strength
    m.attack_chain_n_events = attack_chain.event_count
    m.attack_chain_n_pairs = attack_chain.pair_count
    m.attack_chain_is_cross_domain = bool(attack_chain.is_cross_domain)
    m.attack_connectivity = connectivity
    m.noise_inclusion = noise_inclusion
    m.max_other_chain_strength = max_other
    m.separation_ratio = sep_ratio
    return m


# ============================================================================
# Barridos
# ============================================================================

def sweep_tau_t(pipeline: Pipeline, scenario: Scenario) -> list[dict]:
    rows = []
    for tau in TAU_T_VALUES:
        _, extractor = make_engine_and_extractor(
            pipeline, tau_t=tau, rule_weights=DEFAULT_WEIGHTS,
        )
        chains = extractor.extract(
            min_pair_strength=DEFAULT_THRESHOLD, min_events=2,
        )
        m = compute_metrics(chains, scenario)
        rows.append({
            "scenario": scenario.label,
            "sweep": "tau_t",
            "param_label": f"tau_t={tau:.0f}s",
            "param_numeric": tau,
            **m.__dict__,
        })
    return rows


def sweep_weights(pipeline: Pipeline, scenario: Scenario) -> list[dict]:
    rows = []
    for cfg_name, weights in WEIGHT_CONFIGS.items():
        _, extractor = make_engine_and_extractor(
            pipeline, tau_t=DEFAULT_TAU_T, rule_weights=weights,
        )
        chains = extractor.extract(
            min_pair_strength=DEFAULT_THRESHOLD, min_events=2,
        )
        m = compute_metrics(chains, scenario)
        rows.append({
            "scenario": scenario.label,
            "sweep": "rule_weights",
            "param_label": cfg_name,
            "param_numeric": math.nan,
            **m.__dict__,
        })
    return rows


def sweep_threshold(pipeline: Pipeline, scenario: Scenario) -> list[dict]:
    _, extractor = make_engine_and_extractor(
        pipeline, tau_t=DEFAULT_TAU_T, rule_weights=DEFAULT_WEIGHTS,
    )
    rows = []
    for thresh in THRESHOLD_VALUES:
        chains = extractor.extract(min_pair_strength=thresh, min_events=2)
        m = compute_metrics(chains, scenario)
        rows.append({
            "scenario": scenario.label,
            "sweep": "min_pair_strength",
            "param_label": f"thr={thresh:.2f}",
            "param_numeric": thresh,
            **m.__dict__,
        })
    return rows


# ============================================================================
# Persistencia: CSV
# ============================================================================

def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        print(f"  WARN: no rows to write to {path}")
        return
    # Orden de columnas determinista
    fieldnames = [
        "scenario", "sweep", "param_label", "param_numeric",
        "n_chains",
        "attack_chain_total_strength", "attack_chain_mean_strength",
        "attack_chain_n_events", "attack_chain_n_pairs",
        "attack_chain_is_cross_domain",
        "attack_connectivity", "noise_inclusion",
        "max_other_chain_strength", "separation_ratio",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            row = {k: r.get(k, "") for k in fieldnames}
            writer.writerow(row)


# ============================================================================
# Persistencia: plots (matplotlib opcional)
# ============================================================================

def maybe_import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")  # backend sin display
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        return None


def plot_tau_t(rows: list[dict], path: Path, plt) -> None:
    filt = [r for r in rows if r["sweep"] == "tau_t"]
    if not filt:
        return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    for scenario_label in sorted({r["scenario"] for r in filt}):
        sub = sorted(
            [r for r in filt if r["scenario"] == scenario_label],
            key=lambda r: r["param_numeric"],
        )
        xs = [r["param_numeric"] for r in sub]
        ys_strength = [r["attack_chain_total_strength"] for r in sub]
        ys_connect  = [r["attack_connectivity"] * 100 for r in sub]
        ax1.plot(xs, ys_strength, marker="o", label=scenario_label)
        ax2.plot(xs, ys_connect, marker="o", label=scenario_label)
    for ax, ylabel, title in [
        (ax1, "Strength total de la cadena", "Strength vs τ_t"),
        (ax2, "Cobertura de eventos del ataque (%)", "Connectivity vs τ_t"),
    ]:
        ax.set_xscale("log")
        ax.set_xlabel("τ_t (s, escala logarítmica)")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
        ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_weights(rows: list[dict], path: Path, plt) -> None:
    filt = [r for r in rows if r["sweep"] == "rule_weights"]
    if not filt:
        return
    configs = list(WEIGHT_CONFIGS.keys())  # orden fijo
    scenarios = sorted({r["scenario"] for r in filt})

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))
    width = 0.36
    x = list(range(len(configs)))
    for i, sc in enumerate(scenarios):
        offsets = [xi + (i - (len(scenarios) - 1) / 2) * width for xi in x]
        strengths = []
        seps = []
        for cfg in configs:
            row = next(
                (r for r in filt if r["scenario"] == sc and r["param_label"] == cfg),
                None,
            )
            strengths.append(row["attack_chain_total_strength"] if row else 0.0)
            seps.append(row["separation_ratio"] if row else 0.0)
        ax1.bar(offsets, strengths, width=width, label=sc)
        ax2.bar(offsets, seps, width=width, label=sc)

    for ax, ylabel, title in [
        (ax1, "Strength total de la cadena", "Strength vs configuración de pesos"),
        (ax2, "Separation ratio (ataque / mejor cadena rival)",
         "Separación vs configuración de pesos"),
    ]:
        ax.set_xticks(x)
        ax.set_xticklabels(configs, rotation=15, ha="right")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_threshold(rows: list[dict], path: Path, plt) -> None:
    filt = [r for r in rows if r["sweep"] == "min_pair_strength"]
    if not filt:
        return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    for sc in sorted({r["scenario"] for r in filt}):
        sub = sorted(
            [r for r in filt if r["scenario"] == sc],
            key=lambda r: r["param_numeric"],
        )
        xs = [r["param_numeric"] for r in sub]
        ys_connect = [r["attack_connectivity"] * 100 for r in sub]
        ys_noise   = [r["noise_inclusion"] for r in sub]
        ax1.plot(xs, ys_connect, marker="o", label=sc)
        ax2.plot(xs, ys_noise, marker="o", label=sc)
    ax1.set_xlabel("min_pair_strength")
    ax1.set_ylabel("Cobertura de eventos del ataque (%)")
    ax1.set_title("Connectivity vs umbral")
    ax2.set_xlabel("min_pair_strength")
    ax2.set_ylabel("Eventos ruido absorbidos en la cadena del ataque")
    ax2.set_title("Noise inclusion vs umbral")
    for ax in (ax1, ax2):
        ax.grid(True, alpha=0.3)
        ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


# ============================================================================
# Resumen textual para terminal
# ============================================================================

def print_summary(rows: list[dict]) -> None:
    print("\n" + "=" * 78)
    print("  Resumen rápido (ver CSV y plots para detalle)")
    print("=" * 78)
    for scenario_label in sorted({r["scenario"] for r in rows}):
        print(f"\n  Escenario [{scenario_label}]:")
        # tau_t
        sub = sorted(
            [r for r in rows
             if r["scenario"] == scenario_label and r["sweep"] == "tau_t"],
            key=lambda r: r["param_numeric"],
        )
        if sub:
            print(f"    τ_t sweep:")
            print(f"      {'τ_t':>8} {'strength':>10} {'conn%':>7} {'pairs':>6}")
            for r in sub:
                conn = r["attack_connectivity"] * 100
                print(f"      {r['param_numeric']:>8.0f} "
                      f"{r['attack_chain_total_strength']:>10.3f} "
                      f"{conn:>6.0f}% "
                      f"{r['attack_chain_n_pairs']:>6d}")

        sub = [r for r in rows
               if r["scenario"] == scenario_label and r["sweep"] == "rule_weights"]
        if sub:
            print(f"    rule_weights sweep:")
            print(f"      {'config':>18} {'strength':>10} {'sep ratio':>10} {'conn%':>7}")
            for r in sub:
                conn = r["attack_connectivity"] * 100
                sep = r["separation_ratio"]
                sep_str = f"{sep:.2f}" if sep > 0 else "—"
                print(f"      {r['param_label']:>18} "
                      f"{r['attack_chain_total_strength']:>10.3f} "
                      f"{sep_str:>10} "
                      f"{conn:>6.0f}%")

        sub = sorted(
            [r for r in rows
             if r["scenario"] == scenario_label
             and r["sweep"] == "min_pair_strength"],
            key=lambda r: r["param_numeric"],
        )
        if sub:
            print(f"    threshold sweep:")
            print(f"      {'thr':>5} {'conn%':>7} {'noise abs':>10} {'#chains':>8}")
            for r in sub:
                conn = r["attack_connectivity"] * 100
                print(f"      {r['param_numeric']:>5.2f} "
                      f"{conn:>6.0f}% "
                      f"{r['noise_inclusion']:>10d} "
                      f"{r['n_chains']:>8d}")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    all_rows: list[dict] = []

    for scenario in SCENARIOS:
        if not scenario.db.exists():
            print(f"  SKIP [{scenario.label}]: DB no existe en {scenario.db}")
            continue

        print(f"\n[{scenario.label}] DB: {scenario.db.name}  "
              f"({'con ruido' if scenario.has_noise else 'sin ruido etiquetado'})")
        pipeline = load_pipeline_for_db(scenario.db)
        # Estado inicial
        stats = pipeline.storage.stats()
        print(f"  {stats['events_total']} events, "
              f"{stats['correlations_total']} correlations stored")

        print(f"  Sweep 1/3: tau_t ({len(TAU_T_VALUES)} values)")
        all_rows.extend(sweep_tau_t(pipeline, scenario))
        print(f"  Sweep 2/3: rule_weights ({len(WEIGHT_CONFIGS)} configs)")
        all_rows.extend(sweep_weights(pipeline, scenario))
        print(f"  Sweep 3/3: min_pair_strength ({len(THRESHOLD_VALUES)} values)")
        all_rows.extend(sweep_threshold(pipeline, scenario))

    if not all_rows:
        print("\nNo se ha procesado ningún escenario. Ejecuta primero los scripts\n"
              "  scenario_mmsi (example_mmsi_attack.py) y\n"
              "  scenario_gnss_5g_denial.py\n"
              "para poblar las bases de datos.\n")
        return

    csv_path = OUTPUT_DIR / "sensitivity_results.csv"
    write_csv(all_rows, csv_path)
    print(f"\nCSV escrito: {csv_path}")

    plt = maybe_import_matplotlib()
    if plt is None:
        print("matplotlib no disponible — saltando plots. "
              "Instala con `pip install matplotlib` y vuelve a ejecutar para PNGs.")
    else:
        plot_tau_t(all_rows, OUTPUT_DIR / "sensitivity_tau_t.png", plt)
        plot_weights(all_rows, OUTPUT_DIR / "sensitivity_weights.png", plt)
        plot_threshold(all_rows, OUTPUT_DIR / "sensitivity_threshold.png", plt)
        print(f"Plots escritos en: {OUTPUT_DIR}/")

    print_summary(all_rows)
    print("\nFin.\n")


if __name__ == "__main__":
    main()
