"""Paper figures for the SecureAI governance-pipeline evaluation.
Usage: python make_figures.py e2e_results.json <out_dir>"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
import numpy as np  # noqa: E402

R = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)

# Reference palette (light, print)
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#ffffff"
SEQ = ["#f4f8fd", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica", "Arial", "DejaVu Sans"],
    "font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
    "xtick.labelsize": 8.5, "ytick.labelsize": 8.5, "legend.fontsize": 8.5,
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": AXIS, "axes.linewidth": 0.8, "hatch.linewidth": 0.6,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "pdf.fonttype": 42, "ps.fonttype": 42,
})

A, B = R["v1_15"], R["v2_50"]
NA, NB = A["n"], B["n"]
LAB_A, LAB_B = f"Set A (n = {NA})", f"Set B (n = {NB})"


def style(ax, ygrid=True):
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(axis="both", length=0, pad=4)
    if ygrid:
        ax.yaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)


def bars(ax, x, vals, width, color, hatch, label):
    b = ax.bar(x, vals, width, color=color, edgecolor=SURFACE, linewidth=1.2, hatch=hatch, label=label, zorder=2)
    for rect, v in zip(b, vals):
        ax.annotate(f"{v:.2f}", (rect.get_x() + rect.get_width() / 2, v), xytext=(0, 2.5),
                    textcoords="offset points", ha="center", va="bottom", fontsize=7.5, color=INK)
    return b


def save(fig, name):
    for ext in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"{name}.{ext}", dpi=300, bbox_inches="tight")
    plt.close(fig)


# ── Figure 1: overall classification performance, both sets ─────────────
metrics = [("Decision\naccuracy", lambda r: r["decision"]["accuracy"]),
           ("Decision\nmacro-F1", lambda r: r["decision"]["macro_avg"]["f1"]),
           ("Decision\nweighted-F1", lambda r: r["decision"]["weighted_avg"]["f1"]),
           ("Risk-level\naccuracy", lambda r: r["risk"]["accuracy"]),
           ("Risk-level\nmacro-F1", lambda r: r["risk"]["macro_avg"]["f1"]),
           ("Risk-level\nweighted-F1", lambda r: r["risk"]["weighted_avg"]["f1"])]
fig, ax = plt.subplots(figsize=(6.6, 3.0))
x = np.arange(len(metrics)); w = 0.36
bars(ax, x - w / 2 - 0.01, [f(A) for _, f in metrics], w, S1, None, LAB_A)
bars(ax, x + w / 2 + 0.01, [f(B) for _, f in metrics], w, S2, "////", LAB_B)
ax.set_xticks(x, [m for m, _ in metrics]); ax.set_ylim(0, 1.08); ax.set_ylabel("Score")
ax.set_yticks(np.arange(0, 1.01, 0.2))
style(ax)
ax.legend(loc="upper left", bbox_to_anchor=(0, 1.08), ncol=2, frameon=False, handlelength=1.4, borderaxespad=0)
save(fig, "fig1_overall_performance")

# ── Figure 2: per-class precision / recall / F1 (decision, Set B) ───────
classes = ["ALLOWED", "WARNING", "RESTRICTED"]
per = B["decision"]["per_label"]
fig, ax = plt.subplots(figsize=(5.4, 3.0))
x = np.arange(len(classes)); w = 0.26
for i, (k, c, h) in enumerate((("precision", S1, None), ("recall", S2, "////"), ("f1", S3, "\\\\\\\\"))):
    bars(ax, x + (i - 1) * (w + 0.015), [per[cl][k] for cl in classes], w, c, h,
         {"precision": "Precision", "recall": "Recall", "f1": "F1-score"}[k])
ax.set_xticks(x, [f"{cl.title()}\n(support = {per[cl]['support']})" for cl in classes])
ax.set_ylim(0, 1.08); ax.set_yticks(np.arange(0, 1.01, 0.2)); ax.set_ylabel("Score")
style(ax)
ax.legend(loc="upper left", bbox_to_anchor=(0, 1.08), ncol=3, frameon=False, handlelength=1.4, borderaxespad=0)
save(fig, "fig2_per_class_decision_prf")

# ── Figure 3: confusion matrices (Set B) ────────────────────────────────
cmap = LinearSegmentedColormap.from_list("seq_blue", SEQ)
fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.9))
for ax, (key, labels, title) in zip(axes, (("decision", classes, "(a) Governance decision"),
                                          ("risk", ["LOW", "MEDIUM", "HIGH"], "(b) Risk level"))):
    cm = B[key]["confusion_matrix"]
    M = np.array([[cm[e][p] for p in labels] for e in labels])
    ax.imshow(M, cmap=cmap, vmin=0, vmax=M.max())
    for i in range(3):
        for j in range(3):
            v = M[i, j]
            ax.text(j, i, str(v), ha="center", va="center", fontsize=9.5,
                    fontweight="bold" if i == j else "normal",
                    color="#ffffff" if v > 0.55 * M.max() else INK)
    ax.set_xticks(range(3), [l.title() for l in labels]); ax.set_yticks(range(3), [l.title() for l in labels])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Expected"); ax.set_title(title, loc="left", color=INK, pad=6)
    ax.set_xticks(np.arange(-0.5, 3, 1), minor=True); ax.set_yticks(np.arange(-0.5, 3, 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2); ax.tick_params(which="both", length=0)
    for s in ax.spines.values():
        s.set_visible(False)
fig.tight_layout(w_pad=3)
save(fig, "fig3_confusion_matrices")

# ── Figure 4: end-to-end latency per request ────────────────────────────
fig, ax = plt.subplots(figsize=(4.6, 2.8))
data = [[r["latency_ms"] for r in A["rows"]], [r["latency_ms"] for r in B["rows"]]]
bp = ax.boxplot(data, vert=False, widths=0.42, patch_artist=True, showfliers=False,
                medianprops={"color": INK, "linewidth": 1.4},
                boxprops={"facecolor": "#cde2fb", "edgecolor": S1, "linewidth": 1},
                whiskerprops={"color": S1, "linewidth": 1}, capprops={"color": S1, "linewidth": 1})
rng = np.random.default_rng(7)
for i, d in enumerate(data, start=1):
    ax.scatter(d, i + rng.uniform(-0.13, 0.13, len(d)), s=12, color=S1, edgecolor=SURFACE, linewidth=0.5, zorder=3)
    lat = (A if i == 1 else B)["latency_ms"]
    ax.annotate(f"median {lat['median']:.1f} ms · p95 {lat['p95']:.1f} ms", (max(d), i), xytext=(6, 0),
                textcoords="offset points", va="center", fontsize=7.5, color=INK2)
ax.set_yticks([1, 2], [LAB_A, LAB_B]); ax.set_xlabel("End-to-end /api/chat latency (ms)")
ax.set_xlim(0, max(max(d) for d in data) * 1.9); ax.invert_yaxis()
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
ax.xaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True); ax.tick_params(length=0)
save(fig, "fig4_latency")
print("written:", sorted(p.name for p in OUT.iterdir()))
