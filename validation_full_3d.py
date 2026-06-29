"""Análisis cruzado 3D: τ_t × pesos × umbral.

Combina los tres parámetros del motor en una única matriz tridimensional.
Para cada combinación (τ_t, weight_config, min_pair_strength) y para cada
escenario poblado, mide cómo la cadena del ataque sobrevive al filtrado
y cuánto ruido absorbe.

A diferencia de los análisis previos:
  - validation_sensitivity.py        barridos 1D independientes
  - validation_weights_threshold_cross.py    matriz 2D (pesos × umbral) a τ_t fijo

Este script enumera el cubo completo y, para cada escenario, emite un
heatmap pesos × umbral por cada valor de τ_t, dispuestos en una rejilla
2×3 que permite comparar visualmente cómo se desplaza la región segura
del espacio de parámetros al endurecer o relajar la constante temporal.

Salida
------
  full_3d_output/
    results_3d.csv                        6 × 5 × 7 × 2 = 420 celdas
    grid_mmsi_connectivity.png            1 figura, 6 paneles 2×3
    grid_gnss_5g_connectivity.png         1 figura, 6 paneles 2×3
    grid_gnss_5g_noise.png                1 figura, 6 paneles 2×3

Pre-condición: bases de datos pobladas
  - tfm_system.db                    (escenario MMSI)
  - scenario_gnss_5g.db + .events.json    (escenario GNSS+5G)
"""

from __future__ import annotations

import csv
from pathlib import Path

from validation_sensitivity import (
    SCENARIOS,
    TAU_T_VALUES,
    THRESHOLD_VALUES,
    WEIGHT_CONFIGS,
    Scenario,
    compute_metrics,
    load_pipeline_for_db,
    make_engine_and_extractor,
    maybe_import_matplotlib,
)
from validation_weights_threshold_cross import populate_default_attack_ids


HERE = Path(__file__).parent
OUTPUT_DIR = HERE / "full_3d_output"


# ============================================================================
# Matriz cruzada 3D
# ============================================================================

def run_3d_matrix(pipeline, scenario: Scenario) -> list[dict]:
    """Recorre 6 (τ_t) × 5 (configs) × 7 (thresholds) combinaciones."""
    rows: list[dict] = []
    for tau in TAU_T_VALUES:
        for cfg_name, weights in WEIGHT_CONFIGS.items():
            _, extractor = make_engine_and_extractor(
                pipeline, tau_t=tau, rule_weights=weights,
            )
            for thr in THRESHOLD_VALUES:
                chains = extractor.extract(min_pair_strength=thr, min_events=2)
                m = compute_metrics(chains, scenario)
                rows.append({
                    "scenario": scenario.label,
                    "tau_t": tau,
                    "config": cfg_name,
                    "threshold": thr,
                    **m.__dict__,
                })
    return rows


# ============================================================================
# CSV
# ============================================================================

def write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    fieldnames = [
        "scenario", "tau_t", "config", "threshold",
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
# Heatmaps (grid de τ_t)
# ============================================================================

def _build_matrix(rows, scenario_label, tau_value, metric):
    """Matriz configs × thresholds para un (scenario, τ_t, metric)."""
    configs = list(WEIGHT_CONFIGS.keys())
    thresholds = sorted(THRESHOLD_VALUES)
    matrix = []
    for cfg in configs:
        line = []
        for thr in thresholds:
            cell = next(
                (r for r in rows
                 if r["scenario"] == scenario_label
                 and abs(r["tau_t"] - tau_value) < 1e-9
                 and r["config"] == cfg
                 and abs(r["threshold"] - thr) < 1e-9),
                None,
            )
            line.append(cell[metric] if cell else 0)
        matrix.append(line)
    return configs, thresholds, matrix


def _draw_heatmap(ax, matrix, configs, thresholds, title, fmt, cmap, plt,
                  vmin, vmax, show_ylabels=True, show_xlabels=True):
    im = ax.imshow(matrix, aspect="auto", cmap=cmap, vmin=vmin, vmax=vmax)
    ax.set_xticks(range(len(thresholds)))
    if show_xlabels:
        ax.set_xticklabels([f"{t:.2f}" for t in thresholds], fontsize=8)
        ax.set_xlabel("min_pair_strength", fontsize=9)
    else:
        ax.set_xticklabels([])
    ax.set_yticks(range(len(configs)))
    if show_ylabels:
        ax.set_yticklabels(configs, fontsize=8)
    else:
        ax.set_yticklabels([])
    ax.set_title(title, fontsize=10)
    mid = (vmax + vmin) / 2
    for i in range(len(configs)):
        for j in range(len(thresholds)):
            value = matrix[i][j]
            color = "white" if value < mid else "black"
            ax.text(j, i, fmt(value), ha="center", va="center",
                    color=color, fontsize=7)
    return im


def plot_grid(rows, scenario_label, metric, title_main, fmt, cmap,
              vmin, vmax, path, plt):
    """Genera una figura con 6 paneles (uno por τ_t), rejilla 2×3."""
    fig, axes = plt.subplots(2, 3, figsize=(14, 7))
    taus_sorted = sorted(TAU_T_VALUES)

    last_im = None
    for idx, tau in enumerate(taus_sorted):
        ax = axes[idx // 3, idx % 3]
        configs, thresholds, matrix = _build_matrix(
            rows, scenario_label, tau, metric,
        )
        show_y = (idx % 3 == 0)
        show_x = (idx // 3 == 1)
        last_im = _draw_heatmap(
            ax, matrix, configs, thresholds,
            title=f"τ_t = {int(tau)} s",
            fmt=fmt, cmap=cmap, plt=plt,
            vmin=vmin, vmax=vmax,
            show_ylabels=show_y, show_xlabels=show_x,
        )

    fig.suptitle(title_main, fontsize=12, y=1.00)
    fig.tight_layout(rect=[0, 0, 0.93, 0.97])
    cbar_ax = fig.add_axes([0.945, 0.10, 0.015, 0.80])
    fig.colorbar(last_im, cax=cbar_ax)
    fig.savefig(path, dpi=130, bbox_inches="tight")
    plt.close(fig)


# ============================================================================
# Resumen textual
# ============================================================================

def print_best_combinations(rows: list[dict]) -> None:
    """Para cada escenario, lista las combinaciones que mantienen 100% del
    ataque ordenadas por menor ruido y mayor umbral."""
    print("\n" + "=" * 78)
    print("  Mejores combinaciones (100% del ataque, ordenadas por ruido y umbral)")
    print("=" * 78)
    for scenario_label in sorted({r["scenario"] for r in rows}):
        print(f"\n  Escenario [{scenario_label}]:")
        # Filtrar combinaciones con 100% del ataque
        safe = [r for r in rows
                if r["scenario"] == scenario_label
                and r["attack_connectivity"] >= 0.999]
        if not safe:
            print("    ninguna combinación mantiene el 100% del ataque")
            continue
        # Ordenar: menor ruido primero, luego mayor umbral (más estricto),
        # luego mayor strength
        safe.sort(key=lambda r: (
            r["noise_inclusion"],
            -r["threshold"],
            -r["attack_chain_total_strength"],
        ))
        print(f"    {'τ_t':>6} {'config':>16} {'thr':>5} "
              f"{'noise':>6} {'pairs':>6} {'strength':>10}")
        for r in safe[:10]:
            print(f"    {int(r['tau_t']):>6} {r['config']:>16} "
                  f"{r['threshold']:>5.2f} "
                  f"{r['noise_inclusion']:>6d} "
                  f"{r['attack_chain_n_pairs']:>6d} "
                  f"{r['attack_chain_total_strength']:>10.3f}")


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
        n_cells = len(TAU_T_VALUES) * len(WEIGHT_CONFIGS) * len(THRESHOLD_VALUES)
        print(f"[{scenario.label}] {n_attack} attack ids, {n_noise} noise ids")
        print(f"  Cubo {len(TAU_T_VALUES)} × {len(WEIGHT_CONFIGS)} "
              f"× {len(THRESHOLD_VALUES)} = {n_cells} celdas")
        rows = run_3d_matrix(pipeline, scenario)
        all_rows.extend(rows)

    if not all_rows:
        print("\nNo se ha procesado ningún escenario.")
        return

    csv_path = OUTPUT_DIR / "results_3d.csv"
    write_csv(all_rows, csv_path)
    print(f"\nCSV escrito: {csv_path}")

    plt = maybe_import_matplotlib()
    if plt is None:
        print("matplotlib no disponible — saltando heatmaps.")
    else:
        if any(r["scenario"] == "mmsi" for r in all_rows):
            plot_grid(
                all_rows, "mmsi", "attack_connectivity",
                title_main="MMSI — attack_connectivity (% eventos del ataque conservados)",
                fmt=lambda v: f"{v*100:.0f}%",
                cmap="RdYlGn", vmin=0.0, vmax=1.0,
                path=OUTPUT_DIR / "grid_mmsi_connectivity.png",
                plt=plt,
            )
        if any(r["scenario"] == "gnss_5g" for r in all_rows):
            plot_grid(
                all_rows, "gnss_5g", "attack_connectivity",
                title_main="GNSS+5G — attack_connectivity (% eventos del ataque conservados)",
                fmt=lambda v: f"{v*100:.0f}%",
                cmap="RdYlGn", vmin=0.0, vmax=1.0,
                path=OUTPUT_DIR / "grid_gnss_5g_connectivity.png",
                plt=plt,
            )
            plot_grid(
                all_rows, "gnss_5g", "noise_inclusion",
                title_main="GNSS+5G — eventos de ruido absorbidos en la cadena del ataque",
                fmt=lambda v: f"{int(v)}",
                cmap="RdYlGn_r", vmin=0, vmax=5,
                path=OUTPUT_DIR / "grid_gnss_5g_noise.png",
                plt=plt,
            )
        print(f"Heatmaps en: {OUTPUT_DIR}/")

    print_best_combinations(all_rows)
    print("\nFin.\n")


if __name__ == "__main__":
    main()
