"""Extra experiments for the paper: ARP parameter grid, scan latency by rate/window, analytic Poisson check."""
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                      # makes `import netguard` work from the repo root
RES, FIGS = ROOT / "results", ROOT / "docs" / "figures"

import json, numpy as np
from scipy.stats import poisson
from evaluate import *
res = {}
# E2: ARP (k, W_a) grid, default gateway rule on, pooled over 3 profiles x 20 seeds
data = {p: [gen(p, s) for s in range(20)] for p in PROFILES}
grid = {}
for k in (1, 2, 3):
    for Wa in (5, 10, 30):
        tp = fp = fn = 0
        for p in PROFILES:
            for ev, ae, se, hs in data[p]:
                al = run(ev, ArpDetector(window=Wa, changes=k, use_gateway=True, gateway_ip="10.0.0.1"), PortScanDetector())
                s_ = score(al, ae, se, len(hs)+1, W=Wa)["ARP_SPOOF"]; tp += s_["tp"]; fp += s_["fp"]; fn += s_["fn"]
        P_ = tp/(tp+fp) if tp+fp else 0; R_ = tp/(tp+fn) if tp+fn else 0
        grid[f"{k}|{Wa}"] = dict(tp=tp, fp=fp, fn=fn, P=P_, R=R_, F1=2*P_*R_/(P_+R_) if P_+R_ else 0)
res["arp_grid"] = grid
# E3: scan latency/recall by rate and window (T=15)
lat = {}
for Ws in (10, 30, 60):
    per = {r: [] for r in SCAN_RATES}; hit = {r: [] for r in SCAN_RATES}
    for p in PROFILES:
        for ev, ae, se, hs in data[p]:
            al = run(ev, ArpDetector(gateway_ip="10.0.0.1"), PortScanDetector(window=Ws, threshold=15))
            for (src, t0, t1, rate) in se:
                ts = [a[0] for a in al if a[1] == "PORT_SCAN" and a[2] == src and t0 <= a[0] <= t1 + Ws]
                hit[rate].append(bool(ts))
                if ts: per[rate].append(min(ts) - t0)
    lat[str(Ws)] = {str(r): dict(recall=float(np.mean(hit[r])), n=len(hit[r]), lat=(float(np.mean(per[r])) if per[r] else None)) for r in SCAN_RATES}
res["scan_lat"] = lat
# E4: analytic probability that a single window holds >= T distinct ports (ports assumed distinct), Poisson arrivals
an = {}
for Ws in (10, 30, 60):
    an[str(Ws)] = {str(r): float(1 - poisson.cdf(14, r * Ws)) for r in SCAN_RATES}
res["poisson"] = an
json.dump(res, open(RES / "results_extra.json", "w"), indent=1)
print(json.dumps(res, indent=1))
