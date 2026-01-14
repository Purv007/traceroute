# src/graph_draw.py
import math, os, time
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT_DIR = os.path.join("static", "out")
os.makedirs(OUT_DIR, exist_ok=True)

def _save(fig, name: str) -> str:
    path = os.path.join(OUT_DIR, name)
    fig.savefig(path, bbox_inches="tight", dpi=140)
    plt.close(fig)
    return path

# -------------------- CORONA --------------------

def draw_corona(artifact: dict) -> str:
    nodes = artifact["graph"]["nodes"]
    ms = sorted([n for n in nodes if n["id"].startswith("M")], key=lambda x:int(x["id"][1:]))
    ts = sorted([n for n in nodes if n["id"].startswith("T")], key=lambda x:int(x["id"][1:]))
    n = len(ms)

    fig, ax = plt.subplots(figsize=(5,5))
    ax.axis("off")
    ax.set_aspect("equal")

    R = 2.5
    for i, m in enumerate(ms):
        ang = 2*math.pi*i/n - math.pi/2
        x = R*math.cos(ang); y = R*math.sin(ang)
        m["pos"] = (x, y)

    xs = [m["pos"][0] for m in ms] + [ms[0]["pos"][0]]
    ys = [m["pos"][1] for m in ms] + [ms[0]["pos"][1]]
    ax.plot(xs, ys, color="black", linewidth=2)

    for m in ms:
        x, y = m["pos"]
        ax.scatter([x], [y], s=240, color="white", edgecolors="black", linewidths=1.5, zorder=3)
        ax.text(x, y, str(m["label"]), ha="center", va="center", fontsize=12, weight="bold")

    for i, t in enumerate(ts):
        x0, y0 = ms[i]["pos"]
        ang = math.atan2(y0, x0)
        cx, cy = x0 + 1.2*math.cos(ang), y0 + 1.2*math.sin(ang)
        r = 0.9
        pts = []
        for k in range(5):
            a = ang + 2*math.pi*(k/5.0) + math.pi/5
            pts.append((cx + r*math.cos(a), cy + r*math.sin(a)))
        px = [p[0] for p in pts] + [pts[0][0]]
        py = [p[1] for p in pts] + [pts[0][1]]
        ax.plot(px, py, color="black")
        top = max(pts, key=lambda p:p[1])
        ax.text(top[0], top[1]+0.15, str(t["label"]), ha="center", va="bottom", fontsize=11)
        ax.plot([x0, cx], [y0, cy], color="black")

    name = f"corona_{int(time.time()*1000)}.png"
    return _save(fig, name)

# -------------------- BIPARTITE TABLE --------------------

def draw_bipartite_table(artifact: dict) -> str:
    table = artifact["table"]
    R = artifact["row_primes"]
    C = artifact["col_primes"]
    rows, cols = len(table), len(table[0])

    fig, ax = plt.subplots(figsize=(cols*0.9+1.5, rows*0.9+1.5))
    ax.axis("off")

    # grid
    for r in range(rows+1):
        ax.plot([0, cols], [rows-r, rows-r], color="black", linewidth=1)
    for c in range(cols+1):
        ax.plot([c, c], [0, rows], color="black", linewidth=1)

    # headers
    for j, p in enumerate(C):
        ax.text(j+0.5, rows+0.4, str(p), ha="center", va="bottom", fontsize=12)
    for i, p in enumerate(R):
        ax.text(-0.4, rows-i-0.5, str(p), ha="right", va="center", fontsize=12)

    # cells
    for i in range(rows):
        for j in range(cols):
            ax.text(j+0.5, rows-i-0.5, table[i][j], ha="center", va="center", fontsize=13, weight="bold")

    name = f"table_{int(time.time()*1000)}.png"
    return _save(fig, name)

# -------------------- STAR (PAPER MODE) --------------------
def draw_star(artifact: dict) -> str:
    """
    Robust Star renderer.
    Uses artifact.graph if present; otherwise rebuilds graph from a_values
    with paper rule: w_i = a_i - 10^i (i starts at 1).
    Saves to static/out/star_<ts>.png and returns the full path.
    """
    # Try to read provided graph
    graph = artifact.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    # Fallback: build star from a_values if graph is missing/empty
    if not nodes or not edges:
        a_vals = artifact.get("a_values") or []
        # If still nothing to show, render a simple placeholder
        if not a_vals:
            fig, ax = plt.subplots(figsize=(6,6))
            ax.axis("off")
            ax.text(0.5, 0.5, "No star data (no graph, no a_values)", ha="center", va="center", fontsize=14)
            name = f"star_{int(time.time()*1000)}.png"
            return _save(fig, name)

        # Construct nodes/edges
        nodes = [{"id": "H", "label": 0}]
        edges = []
        for i, aval in enumerate(a_vals, start=1):
            nodes.append({"id": f"L{i}", "label": int(aval)})
            edges.append({"u": "H", "v": f"L{i}", "weight": int(aval - (10**i))})

    # ---- draw ----
    fig, ax = plt.subplots(figsize=(6,6))
    ax.axis("off")
    ax.set_aspect("equal")

    # split nodes
    center = next((n for n in nodes if str(n.get("id")) == "H"), None)
    leaves = sorted(
        [n for n in nodes if str(n.get("id")) != "H"],
        key=lambda x: int(str(x.get("id",""))[1:]) if str(x.get("id","")).startswith("L") and str(x.get("id",""))[1:].isdigit() else 10**9
    )

    # positions
    coords = {"H": (0.0, 0.0)}
    n = max(1, len(leaves))
    R = 2.6
    for i, leaf in enumerate(leaves, start=1):
        ang = 2*math.pi*(i-1)/n - math.pi/2
        coords[leaf["id"]] = (R*math.cos(ang), R*math.sin(ang))

    # edges with weights
    for e in edges:
        u, v = e.get("u"), e.get("v")
        (x1, y1) = coords.get(u, (0,0))
        (x2, y2) = coords.get(v, (0,0))
        ax.plot([x1, x2], [y1, y2], color="black", linewidth=1.6)
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my, str(e.get("weight","")), fontsize=10, ha="center", va="center")

    # center node
    cx, cy = coords["H"]
    center_label = (center or {}).get("label", 0)
    ax.scatter([cx], [cy], s=260, color="white", edgecolors="black", linewidths=1.6, zorder=3)
    ax.text(cx, cy, str(center_label), ha="center", va="center", fontsize=12, weight="bold")
    ax.text(cx, cy-0.18, "H", fontsize=9, ha="center", va="top")

    # leaf nodes
    for leaf in leaves:
        x, y = coords[leaf["id"]]
        ax.scatter([x], [y], s=240, color="white", edgecolors="black", linewidths=1.4, zorder=3)
        ax.text(x, y, str(leaf.get("label","")), fontsize=12, ha="center", va="center", weight="bold")
        ax.text(x, y-0.18, leaf["id"], fontsize=9, ha="center", va="top")

    ax.set_title("Star Graph (Paper Mode)", fontsize=13)
    name = f"star_{int(time.time()*1000)}.png"
    return _save(fig, name)

