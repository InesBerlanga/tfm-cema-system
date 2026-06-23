"""Análisis cruzado pesos × umbral.

Por cada combinación (configuración de pesos, umbral de min_pair_strength) y
para cada escenario poblado en disco, mide cómo la cadena del ataque
sobrevive al filtrado y cuánto ruido absorbe. Reutiliza la infraestructura
de validation_sensitivity.py (compute_metrics, WEIGHT_CONFIGS, etc.).

A diferencia del barrido individual de pesos (que se ejecuta solo a
umbral=0 y solo da diferencias en strength absoluta), este experimento
discrimina entre configuraciones por su comportamiento BAJO FILTRADO:

  - ¿qué configuración mantiene 100% del ataque hasta el umbral más alto?
  - ¿qué configuración deja caer el ruido antes sin romper el ataque?

Salida
------
  weights_threshold_output/
    weights_threshold_results.csv     35 celdas/escenario (5 configs × 7 thr)
    weights_threshold_mmsi.png        heatmap connectivity (MMSI)
    weights_threshold_gnss_5g.png     heatmaps connectivity + noise (GNSS+5G)

Pre-condición: bases de datos pobladas:
  - tfm_system.db                     (escenario MMSI)
  - scenario_gnss_5g.db + .events.json (escenario GNSS+5G)
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from validation_sensitivity import (
    DEFAULT_TAU_T,
    SCENARIOS,
    THRESHOLD_VALUES,
    WEIGHT_CONFIGS,
    Scenario,
    compute_metrics,
    load_pipeline_for_db,
    make_engine_and_extractor,
    maybe_import_matplotlib,
)


HERE = Path(__file__).parent
OUTPUT_DIR = HERE / "weights_threshold_output"


# ============================================================================
# Helper para resolver el "ground truth" de attack_ids cuando no hay sidecar
# ============================================================================

def populate_default_attack_ids(scenario: Scenario, pipeline) -> None:
    """Si el escenario no trae sidecar (caso MMSI), tratamos TODOS los eventos
    de la BD como ataque. Esto hace que `attack_connectivity` mida la
    fragmentación real del ataque (event_count / total_events) y no devuelva
    1.0 tautológicamente.
    """
    if scenario.attack_ids:
        return
    # Query directa al SQLite del storage
    with pipeline.storage._connect() as conn:
        rows = conn.execute("SELECT event_id FROM classified_events").fetchall()
        scenario.attack_ids = {row[0] for row in rows}


# ============================================================================
# Matriz cruzada
# ============================================================================

def run_cross_matrix(pipeline, scenario: Scenario) -> list[dict]:
    """Recorre 5 × 7 combinaciones (configs × thresholds)."""
    rows: list[dict] = []
    for cfg_name, weights in WEIGHT_CONFIGS.items():
        _, extractor = make_engine_and_extractor(
            pipeline, tau_t=DEFAULT_TAU_T, rule_weights=weights,
        )
        for thr in THRESHOLD_VALUES:
            chains = extractor.extract(min_pair_strength=thr, min_events=2)
            m = compute_metrics(chains, scenario)
            rows.append({
                "scenario": scenario.label,
                "config": cfg_name,
                "threshold": thr,
                **m.__dict__,
            })
    return rows


# ============================================================================
# Resumen: para cada (scenario, config), umbral máximo seguro
# ============================================================================

@dataclass
class ConfigSummary:
    scenario: str
    config: str
    max_safe_threshold: float    # umbral máximo manteniendo connectivity == 100%
    noise_at_max: int            # ruido absorbido en ese umbral
    pairs_at_max: int            # nº de pares de la cadena en ese umbral
    strength_at_max: float


def summarize(rows: list[dict]) -> list[ConfigSummary]:
    """Para cada (scenario, config) busca el umbral máximo donde la
    connectivity sigue siendo 100% y reporta el ruido absorbido en ese punto.
    Cuanto mayor el umbral seguro y menor el ruido, mejor la configuración.
    """
    by_key: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        by_key.setdefault((r["scenario"], r["config"]), []).append(r)

    summaries: list[ConfigSummary] = []
    for (sc, cfg), points in by_key.items():
        points.sort(key=lambda r: r["threshold"])
        max_safe: Optional[dict] = None
        for r in points:
            if r["attack_connectivity"] >= 0.999:  # tolerancia float
                max_safe = r
            else:
                break  # una vez cae, no vuelve a subir al subir el umbral
        if max_safe is None:
            # No hay ningún umbral seguro (ni siquiera 0.0 mantiene 100%)
            max_safe = points[0]
            summaries.append(ConfigSummary(
                scenario=sc, config=cfg,
                max_safe_threshold=-1.0,
                noise_at_max=max_safe["noise_inclusion"],
                pairs_at_max=max_safe["attack_chain_n_pairs"],
                strength_at_max=max_safe["attack_chain_total_strength"],
            ))
        else:
            summaries.append(ConfigSummary(
                scenario=sc, config=cfg,
                max_safe_threshold=max_safe["threshold"],
                noise_at_max=max_safe["noise_inclusion"],
                pairs_at_max=max_safe["attack_chain_n_pairs"],
                strength_at_max=max_safe["attack_chain_total_strength"],
            ))
    return summaries


# ============================================================================
# CSV
# ============================================================================

def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    fieldnames = [
        "scenario", "config", "threshold",
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
            writer.writerow({k: r.get(k, "") for k in fieldnames})


# ============================================================================
# Heatmaps
# ============================================================================

def _build_matrix(rows, scenario_label, metric):
    """Construye una matriz numpy-like (lista de listas) configs × thresholds."""
    configs = list(WEIGHT_CONFIGS.keys())
    thresholds = sorted(THRESHOLD_VALUES)
    matrix = []
    for cfg in configs:
        line = []
        for thr in thresholds:
            cell = next(
                (r for r in rows
                 if r["scenario"] == scenario_label
                 and r["config"] == cfg
                 and abs(r["threshold"] - thr) < 1e-9),
                None,
            )
            line.append(cell[metric] if cell else 0)
        matrix.append(line)
    return configs, thresholds, matrix


def _draw_heatmap(ax, matrix, configs, thresholds, title, fmt, cmap, plt,
                  vmin=None, vmax=None):
    """Dibuja un heatmap anotado en el axes dado."""
    im = ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=vmin, vmax=vmax)
    ax.set_xticks(range(len(thresholds)))
    ax.set_xticklabels([f"{t:.2f}" for t in thresholds])
    ax.set_yticks(range(len(configs)))
    ax.set_yticklabels(configs)
    ax.set_xlabel("min_pair_strength")
    ax.set_ylabel("rule_weights")
    ax.set_title(title)
    # Anotaciones por celda
    rng = (vmax - vmin) if (vmax is not None and vmin is not None) else 1
    mid = (vmax + vmin) / 2 if (vmax is not None and vmin is not None) else None
    for i, cfg in enumerate(configs):
        for j, _ in enumerate(thresholds):
            value = matrix[i][j]
            text = fmt(value)
            # Color del texto: blanco sobre celdas oscuras, negro sobre claras
            if mid is not None:
                color = "white" if value < mid else "black"
            else:
                color = "black"
            ax.text(j, i, text, ha="center", va="center", color=color, fontsize=9)
    plt.colorbar(im, ax=ax, fraction=0.04, pad=0.04)


def plot_mmsi(rows: list[dict], path: Path, plt) -> None:
    configs, thresholds, conn_matrix = _build_matrix(
        rows, "mmsi", "attack_connectivity",
    )
    _, _, count_matrix = _build_matrix(rows, "mmsi", "attack_chain_n_events")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.5))
    _draw_heatmap(
        ax1, conn_matrix, configs, thresholds,
        title="MMSI — attack_connectivity",
        fmt=lambda v: f"{v*100:.0f}%",
        cmap="RdYlGn", vmin=0.0, vmax=1.0, plt=plt,
    )
    _draw_heatmap(
        ax2, count_matrix, configs, thresholds,
        title="MMSI — eventos en la cadena",
        fmt=lambda v: f"{int(v)}",
        cmap="YlGnBu", vmin=0, vmax=8, plt=plt,
    )
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_gnss_5g(rows: list[dict], path: Path, plt) -> None:
    configs, thresholds, conn_matrix = _build_matrix(
        rows, "gnss_5g", "attack_connectivity",
    )
    _, _, noise_matrix = _build_matrix(rows, "gnss_5g", "noise_inclusion")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.5))
    _draw_heatmap(
        ax1, conn_matrix, configs, thresholds,
        title="GNSS+5G — attack_connectivity",
        fmt=lambda v: f"{v*100:.0f}%",
        cmap="RdYlGn", vmin=0.0, vmax=1.0, plt=plt,
    )
    # Para noise: 0 (verde, bueno) → 5 (rojo, malo)
    _draw_heatmap(
        ax2, noise_matrix, configs, thresholds,
        title="GNSS+5G — ruido absorbido",
        fmt=lambda v: f"{int(v)}",
        cmap="RdYlGn_r", vmin=0, vmax=5, plt=plt,
    )
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


# ============================================================================
# Impresión
# ============================================================================

def print_summary(summaries: list[ConfigSummary]) -> None:
    print("\n" + "=" * 78)
    print("  Resumen cruzado pesos × umbral")
    print("  (max_safe_thr = umbral máximo manteniendo 100% del ataque)")
    print("=" * 78)

    for scenario_label in sorted({s.scenario for s in summaries}):
        subset = [s for s in summaries if s.scenario == scenario_label]
        # Orden de WEIGHT_CONFIGS preservado
        subset.sort(key=lambda s: list(WEIGHT_CONFIGS.keys()).index(s.config))
        print(f"\n  Escenario [{scenario_label}]:")
        print(f"    {'config':>18} {'max_safe_thr':>14} "
              f"{'noise@max':>11} {'pairs@max':>10} {'strength@max':>13}")
        for s in subset:
            thr_str = (
                f"{s.max_safe_threshold:.2f}"
                if s.max_safe_threshold >= 0 else "—"
            )
            print(f"    {s.config:>18} {thr_str:>14} "
                  f"{s.noise_at_max:>11} "
                  f"{s.pairs_at_max:>10} "
                  f"{s.strength_at_max:>13.3f}")

    # Ranking: para cada escenario, ordenar configs por (max_safe_thr desc, noise asc)
    print("\n  Ranking por escenario (mayor umbral seguro / menor ruido a ese umbral):")
    for scenario_label in sorted({s.scenario for s in summaries}):
        subset = [s for s in summaries if s.scenario == scenario_label]
        subset.sort(key=lambda s: (-s.max_safe_threshold, s.noise_at_max))
        order = " > ".join(s.config for s in subset)
        print(f"    [{scenario_label}]: {order}")


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
        pipeline = load_pipeline_for_db(scenario.db)
        populate_default_attack_ids(scenario, pipeline)
        n_attack = len(scenario.attack_ids)
        n_noise = len(scenario.noise_ids)
        print(f"[{scenario.label}] {n_attack} attack ids, {n_noise} noise ids")
        print(f"  Matriz 5 configs × {len(THRESHOLD_VALUES)} thresholds = "
              f"{5 * len(THRESHOLD_VALUES)} celdas")
        rows = run_cross_matrix(pipeline, scenario)
        all_rows.extend(rows)

    if not all_rows:
        print("\nNo se ha procesado ningún escenario.")
        return

    csv_path = OUTPUT_DIR / "weights_threshold_results.csv"
    write_csv(all_rows, csv_path)
    print(f"\nCSV escrito: {csv_path}")

    plt = maybe_import_matplotlib()
    if plt is None:
        print("matplotlib no disponible — saltando heatmaps.")
    else:
        if any(r["scenario"] == "mmsi" for r in all_rows):
            plot_mmsi(all_rows, OUTPUT_DIR / "weights_threshold_mmsi.png", plt)
        if any(r["scenario"] == "gnss_5g" for r in all_rows):
            plot_gnss_5g(all_rows, OUTPUT_DIR / "weights_threshold_gnss_5g.png", plt)
        print(f"Heatmaps en: {OUTPUT_DIR}/")

    summaries = summarize(all_rows)
    print_summary(summaries)
    print("\nFin.\n")


if __name__ == "__main__":
    main()
