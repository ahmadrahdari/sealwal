"""Render the README charts from results/*.csv.

    python bench/plot.py
"""

from __future__ import annotations

import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "..", "results")

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
# same configuration -> same color in every chart
STYLE = {
    ("none", "inline"): dict(color="#8a8984", ls=(0, (4, 3)), label="no signature"),
    ("ed25519", "inline"): dict(color="#2a78d6", ls="-", label="Ed25519 inline"),
    ("ml-dsa-65", "inline"): dict(color="#eb6834", ls="-", label="ML-DSA-65 inline"),
    ("ml-dsa-65", "async"): dict(color="#1baf7a", ls="-", label="ML-DSA-65 async"),
    ("lms-hss", "inline"): dict(color="#eda100", ls="-", label="epoch HSS inline"),
}


def load(name):
    with open(os.path.join(RESULTS, name)) as f:
        return list(csv.DictReader(f))


def setup(ax, title, ylabel, xlabel):
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=INK, fontsize=11.5, pad=12, fontweight="bold")
    ax.set_ylabel(ylabel, color=INK2, fontsize=9.5)
    ax.set_xlabel(xlabel, color=INK2, fontsize=9.5)
    ax.grid(axis="y", color=GRID, lw=1, ls="-")
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)


def flush_sweep():
    rows = load("flush_sweep.csv")
    flushes = sorted({int(r["flush_us"]) for r in rows})
    fig, ax = plt.subplots(figsize=(7.4, 4.3), dpi=160)
    fig.patch.set_facecolor(SURFACE)
    setup(ax, "Single-record commit latency vs. flush latency (emulated, p50)",
          "commit latency, µs", "flush latency of the log, µs")
    for key in [("ml-dsa-65", "inline"), ("lms-hss", "inline"), ("ed25519", "inline"),
                ("ml-dsa-65", "async"), ("none", "inline")]:
        st = STYLE[key]
        ys = [float(next(r["p50"] for r in rows if (r["alg"], r["mode"]) == key
                         and int(r["flush_us"]) == f)) for f in flushes]
        ax.plot(flushes, ys, color=st["color"], ls=st["ls"], lw=2, label=st["label"], zorder=3)
        ax.plot(flushes, ys, "o", ms=7, color=st["color"], mec=SURFACE, mew=2, zorder=4)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xticks(flushes, [str(f) for f in flushes])
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:,.0f}"))
    # the lines meet at slow flushes, so the legend carries identity
    ax.legend(frameon=False, fontsize=9, loc="upper left", labelcolor=INK, ncol=2)
    ax.set_ylim(10, 4000)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "flush_sweep.png"), facecolor=SURFACE)


def k_sweep():
    rows = load("ksweep.csv")
    ks = [r["K"] for r in rows]
    xs = list(range(len(ks)))
    labels = ["∞" if k == "inf" else k for k in ks]
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.4, 3.4), dpi=160)
    fig.patch.set_facecolor(SURFACE)
    setup(a, "Throughput", "committed records/s", "bound K")
    setup(b, "Authentication window", "p99, ms", "bound K")
    for ax, col, color, fmt in [(a, "rps", "#1baf7a", "{:,.0f}"), (b, "window_p99_ms", "#eb6834", "{:.1f}")]:
        ys = [float(r[col]) for r in rows]
        ax.plot(xs, ys, color=color, lw=2, zorder=3)
        ax.plot(xs, ys, "o", ms=7, color=color, mec=SURFACE, mew=2, zorder=4)
        for x, y in [(xs[0], ys[0]), (xs[-1], ys[-1])]:
            ax.annotate(fmt.format(y), (x, y), xytext=(0, 9), textcoords="offset points",
                        ha="center", fontsize=8.5, color=INK)
        ax.set_xticks(xs, labels)
        ax.set_ylim(0, max(ys) * 1.2)
    a.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: f"{v:,.0f}"))
    fig.suptitle("ML-DSA-65, async signing, 16 clients, fdatasync", x=0.02, ha="left",
                 fontsize=9, color=INK2, y=0.99)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "ksweep.png"), facecolor=SURFACE)


if __name__ == "__main__":
    flush_sweep()
    k_sweep()
    print("wrote results/flush_sweep.png and results/ksweep.png")
