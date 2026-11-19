"""Render the README charts from results/*.csv.

    python bench/plot.py
"""

from __future__ import annotations

import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
# Same entity -> same color in every chart.
STYLE = {
    "none": dict(color="#8a8984", ls=(0, (4, 3)), label="no signature (baseline)"),
    "ed25519": dict(color="#2a78d6", ls="-", label="Ed25519, inline"),
    "ml-dsa-65": dict(color="#eb6834", ls="-", label="ML-DSA-65, inline"),
    "ml-dsa-65-async": dict(color="#1baf7a", ls="-", label="ML-DSA-65, async"),
}


def load(name):
    with open(os.path.join(RESULTS, name)) as f:
        return list(csv.DictReader(f))


def setup(ax, title, ylabel, xlabel):
    fig = ax.figure
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=INK, fontsize=12.5, pad=14, fontweight="bold")
    ax.set_ylabel(ylabel, color=INK2, fontsize=10)
    ax.set_xlabel(xlabel, color=INK2, fontsize=10)
    ax.grid(axis="y", color=GRID, lw=1, ls="-")
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)


def line(ax, xs, ys, key, end_label):
    st = STYLE[key]
    ax.plot(xs, ys, color=st["color"], ls=st["ls"], lw=2, solid_capstyle="round", solid_joinstyle="round",
            label=st["label"], zorder=3)
    ax.plot(xs, ys, "o", ms=8, color=st["color"], mec=SURFACE, mew=2, zorder=4)
    if end_label is None:  # converging lines: the legend carries identity
        return
    ax.annotate(end_label, (xs[-1], ys[-1]), xytext=(10, 0), textcoords="offset points",
                va="center", fontsize=9, color=INK)


def commit_latency():
    rows = [r for r in load("batch_sweep.csv") if r["alg"] in ("none", "ed25519", "ml-dsa-65")]
    batches = sorted({int(r["batch"]) for r in rows})
    xs = list(range(len(batches)))
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=160)
    setup(ax, "Commit latency (p50) by batch size, one writer, fdatasync",
          "commit latency, µs (median)", "records per commit")
    for alg, lab in [("ml-dsa-65", "ML-DSA-65"), ("ed25519", "Ed25519"), ("none", "none")]:
        ys = [float(next(r for r in rows if r["alg"] == alg and int(r["batch"]) == b)["commit_p50_us"])
              for b in batches]
        line(ax, xs, ys, alg, f"{lab}  {ys[-1]:,.0f} µs" if alg == "ml-dsa-65" else None)
    ax.set_xticks(xs, [str(b) for b in batches])
    ax.set_ylim(0, None)
    ax.set_xlim(-0.3, len(xs) - 0.2)
    ax.legend(frameon=False, fontsize=9, loc="upper left", labelcolor=INK)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "commit_latency.png"), facecolor=SURFACE)


def group_commit():
    rows = load("group_commit.csv")
    clients = sorted({int(r["clients"]) for r in rows})
    xs = list(range(len(clients)))
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=160)
    setup(ax, "Group-commit throughput by number of client threads",
          "committed records per second", "concurrent clients")
    for alg, mode, key, lab in [
        ("ml-dsa-65", "async", "ml-dsa-65-async", "ML-DSA-65 async"),
        ("none", "inline", "none", "none"),
        ("ed25519", "inline", "ed25519", "Ed25519"),
        ("ml-dsa-65", "inline", "ml-dsa-65", "ML-DSA-65 inline"),
    ]:
        ys = [float(next(r for r in rows if r["alg"] == alg and r["mode"] == mode
                         and int(r["clients"]) == c)["records_per_s"]) for c in clients]
        line(ax, xs, ys, key, lab)
    ax.set_xticks(xs, [str(c) for c in clients])
    ax.set_ylim(0, None)
    ax.set_xlim(-0.3, len(xs) + 0.35)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _p: f"{v:,.0f}"))
    ax.legend(frameon=False, fontsize=9, loc="upper left", labelcolor=INK)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "group_commit.png"), facecolor=SURFACE)


if __name__ == "__main__":
    commit_latency()
    group_commit()
    print("wrote results/commit_latency.png and results/group_commit.png")
