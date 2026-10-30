"""Reproducible evaluation of NetGuard on SYNTHETIC labelled traffic (3 network profiles x 20 seeds)."""
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                      # makes `import netguard` work from the repo root
RES, FIGS = ROOT / "results", ROOT / "docs" / "figures"

import random, json, time, statistics as st
from netguard import ArpDetector, PortScanDetector
import numpy as np
from scipy.stats import wilcoxon

PROFILES = {  # hosts, benign_conn_rate(per host per s), noisy benign hosts, benign MAC changes, arp attacks, scans
 "Home":   dict(hosts=6,   rate=0.4, noisy=0, macchg=1, flap=1, arp=2, scans=4),
 "Hostel": dict(hosts=40,  rate=0.8, noisy=3, macchg=4, flap=3, arp=3, scans=8),
 "Campus": dict(hosts=120, rate=1.2, noisy=10, macchg=10, flap=6, arp=4, scans=12),
}
DUR = 600.0
COMMON = [80, 443, 53, 22, 25, 110, 143, 993, 8080, 123, 5222, 3478]
SCAN_RATES = [50, 10, 2, 0.5]       # packets/s: fast, medium, slow, stealth

def gen(profile, seed):
    p, r = PROFILES[profile], random.Random(seed)
    ev, arp_eps, scan_eps = [], [], []
    mac = lambda: ":".join(f"{r.randrange(256):02x}" for _ in range(6))
    gw_ip, gw_mac = "10.0.0.1", mac()
    hosts = {f"10.0.{1+i//250}.{2+i%250}": mac() for i in range(p["hosts"])}
    ev.append(("arp", 0.0, gw_ip, gw_mac))
    for ip, m in hosts.items(): ev.append(("arp", r.uniform(0, 5), ip, m))
    # benign periodic ARP refresh + browsing/service connections
    nm = min(p["macchg"], len(hosts)); pool = r.sample(list(hosts), min(nm + p["flap"], len(hosts)))
    chg = {}            # ip -> sorted [(time, mac)]; single change (NIC swap) or flapping (Wi-Fi/Ethernet switch, >=60 s apart)
    for ip in pool[:nm]: chg[ip] = [(r.uniform(60, DUR-60), mac())]
    for ip in pool[nm:]:
        alt = [hosts[ip], mac()]; ts_ = sorted(r.sample(range(60, int(DUR)-60, 10), 3)); ts_ = [x for i, x in enumerate(ts_) if i == 0 or x - ts_[i-1] >= 60] or [ts_[0]]
        chg[ip] = [(float(x), alt[(i+1) % 2]) for i, x in enumerate(ts_)]
    def mac_at(ip, t):
        m = hosts.get(ip, gw_mac)
        for (tc, mc) in chg.get(ip, []):
            if t >= tc: m = mc
        return m
    for ip in list(hosts) + [gw_ip]:
        t = r.uniform(0, 30)
        while t < DUR: ev.append(("arp", t, ip, mac_at(ip, t))); t += r.uniform(20, 60)
    for i, ip in enumerate(hosts):
        t = r.uniform(0, 3)
        while t < DUR:
            t += r.expovariate(p["rate"])
            ev.append(("tcp", t, ip, f"93.184.{r.randrange(256)}.{r.randrange(256)}", r.choice(COMMON), r.random() < .45))
            if r.random() < .6:    # established-flow ACK traffic to many ephemeral ports (non-SYN)
                ev.append(("tcp", t+.01, ip, "10.0.0.1", r.randrange(1024, 65535), False))
    # hard negatives: noisy benign hosts (P2P/service discovery: many SYNs to varied ports, slow)
    for ip in list(hosts)[:p["noisy"]]:
        t = r.uniform(0, 60)
        while t < DUR:
            t += r.expovariate(1.0)
            ev.append(("tcp", t, ip, f"198.51.{r.randrange(256)}.{r.randrange(256)}", r.choice(COMMON+[6881,6969,51413,4662]), True))
    # hard negatives: benign bursts to ONE server across several ports (passive FTP, RPC, admin checks)
    for ip in r.sample(list(hosts), min(max(2, p["noisy"]), len(hosts))):
        for _ in range(r.randrange(2, 6)):
            t = r.uniform(10, DUR-20); srv = f"10.0.5.{r.randrange(2,20)}"
            for prt in r.sample(range(1024, 65535), r.randrange(3, 14)):
                t += r.uniform(.05, .6); ev.append(("tcp", t, ip, srv, prt, True))
    # hard negatives: legitimate MAC changes (NIC swap / DHCP re-lease) - single change
    for ip, lst in chg.items():
        for (t, m2) in lst: ev.append(("arp", t, ip, m2))      # legit change: later refreshes use the new MAC
    # ARP spoofing attacks: ~60% on the gateway, ~40% on an ordinary host (attacker poisons every 1.5-3 s; owner refreshes interleave)
    stable = [h for h in hosts if h not in chg]
    for _ in range(p["arp"]):
        victim = gw_ip if (r.random() < .6 or not stable) else r.choice(stable); vmac = gw_mac if victim == gw_ip else hosts[victim]
        t0 = r.uniform(30, DUR-90); t1 = t0 + r.uniform(20, 60); am = mac(); t = t0
        while t < t1:
            ev.append(("arp", t, victim, am)); ev.append(("arp", t+r.uniform(.3, 1.2), victim, vmac)); t += r.uniform(1.5, 3)
        arp_eps.append((victim, t0, t1))
    # port scans from distinct attacker IPs
    for k in range(p["scans"]):
        src = f"10.0.9.{10+k}"; rate = SCAN_RATES[k % 4]; tgt = r.choice(list(hosts))
        t0 = r.uniform(30, DUR-150); nports = r.choice([100, 200, 500, 1000]); t = t0
        for prt in r.sample(range(1, 65535), nports):
            t += r.expovariate(rate)
            if t > DUR: break
            ev.append(("tcp", t, src, tgt, prt, True))
        scan_eps.append((src, t0, t, rate))
    ev.sort(key=lambda e: e[1])
    return ev, arp_eps, scan_eps, list(hosts)

def run(ev, arp_det, scan_det):
    out = []
    for e in ev:
        a = arp_det.process(e[1], e[2], e[3]) if e[0] == "arp" else scan_det.process(e[1], e[2], e[3], e[4], e[5])
        if a: out.append((e[1], a[0], a[1]))
    return out

def score(alerts, arp_eps, scan_eps, nhosts, W=10.0):
    res = {}
    for kind, eps in (("ARP_SPOOF", arp_eps), ("PORT_SCAN", scan_eps)):
        al = [a for a in alerts if a[1] == kind]; used = set(); tp = 0; lat = []
        for ep in eps:
            key, t0, t1 = ep[0], ep[1], ep[2]
            hit = [a for a in al if a[2] == key and t0 <= a[0] <= t1 + W]
            if hit: tp += 1; lat.append(min(a[0] for a in hit) - t0); used.update(id(a) for a in hit)
        fp = len([a for a in al if id(a) not in used]); fn = len(eps) - tp
        slots = max(1, int(nhosts * DUR / W)); tn = max(0, slots - fp)
        P = tp/(tp+fp) if tp+fp else 0.0; R = tp/(tp+fn) if tp+fn else 0.0
        F = 2*P*R/(P+R) if P+R else 0.0
        res[kind] = dict(tp=tp, fp=fp, fn=fn, tn=tn, P=P, R=R, F1=F, FPR=fp/(fp+tn), lat=lat)
    return res

CONFIGS = {   # name -> (arp kwargs, scan kwargs)
 "NetGuard (full)":            (dict(window=10, changes=2, use_gateway=True), dict(window=10, threshold=15, syn_only=True)),
 "Naive (any MAC change / cumulative ports)": (dict(window=1e9, changes=1, use_gateway=False, cooldown=10), dict(window=1e9, threshold=15, syn_only=False, per_dst=False, cooldown=10)),
 "- gateway rule":             (dict(window=10, changes=2, use_gateway=False), dict(window=10, threshold=15, syn_only=True)),
 "- windowed change rule":     (dict(window=10, changes=10**9, use_gateway=True), dict(window=10, threshold=15, syn_only=True)),
 "- time window":              (dict(window=1e9, changes=2, use_gateway=True, cooldown=10), dict(window=1e9, threshold=15, syn_only=True, cooldown=10)),
 "- SYN-only filter":          (dict(window=10, changes=2, use_gateway=True), dict(window=10, threshold=15, syn_only=False)),
 "- per-destination grouping": (dict(window=10, changes=2, use_gateway=True), dict(window=10, threshold=15, syn_only=True, per_dst=False)),
 "k=1 (single change)":        (dict(window=10, changes=1, use_gateway=True), dict(window=10, threshold=15, syn_only=True)),
}
def build(cfg, gw="10.0.0.1"):
    a, s = CONFIGS[cfg]; return ArpDetector(gateway_ip=gw, **a), PortScanDetector(**s)

if __name__ == "__main__":
    SEEDS = range(20); R = {}
    for prof in PROFILES:
        data = [gen(prof, s) for s in SEEDS]
        R[prof] = {}
        for cfg in CONFIGS:
            rows = []
            for ev, ae, se, hs in data:
                al = run(ev, *build(cfg)); rows.append(score(al, ae, se, len(hs)+1))
            R[prof][cfg] = rows
    json.dump(R, open(RES / "raw_results.json", "w"))
    # summary
    summ = {}
    for prof in R:
        summ[prof] = {}
        for cfg, rows in R[prof].items():
            summ[prof][cfg] = {}
            for kind in ("ARP_SPOOF", "PORT_SCAN"):
                g = lambda k: [x[kind][k] for x in rows]
                tp, fp, fn, tn = (sum(g(k)) for k in ("tp", "fp", "fn", "tn"))
                P = tp/(tp+fp) if tp+fp else 0; Rc = tp/(tp+fn) if tp+fn else 0
                F = 2*P*Rc/(P+Rc) if P+Rc else 0
                lats = [l for x in rows for l in x[kind]["lat"]]
                summ[prof][cfg][kind] = dict(P=P, R=Rc, F1=F, FPR=fp/(fp+tn), tp=tp, fp=fp, fn=fn,
                    f1_mean=float(np.mean(g("F1"))), f1_sd=float(np.std(g("F1"))),
                    lat=float(np.mean(lats)) if lats else None)
    # Wilcoxon: full vs naive, per-seed F1, pooled across profiles
    stats = {}
    for kind in ("ARP_SPOOF", "PORT_SCAN"):
        for base in ("Naive (any MAC change / cumulative ports)", "- SYN-only filter", "- per-destination grouping", "- gateway rule", "- windowed change rule", "- time window", "k=1 (single change)"):
            a = [x[kind]["F1"] for p in R for x in R[p]["NetGuard (full)"]]
            b = [x[kind]["F1"] for p in R for x in R[p][base]]
            if all(x == y for x, y in zip(a, b)): stats[f"{kind}|{base}"] = dict(stat=0.0, p=1.0, md=0.0); continue
            try: w = wilcoxon(a, b); stats[f"{kind}|{base}"] = dict(stat=float(w.statistic), p=float(w.pvalue), md=float(np.mean(a)-np.mean(b)))
            except ValueError: stats[f"{kind}|{base}"] = dict(stat=None, p=None, md=float(np.mean(a)-np.mean(b)))
    # scan recall by speed (full config)
    byrate = {}
    for prof in PROFILES:
        for s in SEEDS:
            ev, ae, se, hs = gen(prof, s); al = run(ev, *build("NetGuard (full)"))
            for (src, t0, t1, rate) in se:
                hit = any(a[1] == "PORT_SCAN" and a[2] == src and t0 <= a[0] <= t1+10 for a in al)
                byrate.setdefault(rate, []).append(hit)
    byrate = {str(k): (sum(v)/len(v), len(v)) for k, v in byrate.items()}
    # threshold sweep (Hostel)
    sweep = {}
    data = [gen("Hostel", s) for s in SEEDS]
    for T in (5, 10, 15, 20, 30, 50):
        for W in (5, 10, 30):
            tp=fp=fn=0
            for ev, ae, se, hs in data:
                al = run(ev, ArpDetector(gateway_ip="10.0.0.1"), PortScanDetector(window=W, threshold=T))
                s_ = score(al, ae, se, len(hs)+1)["PORT_SCAN"]; tp+=s_["tp"]; fp+=s_["fp"]; fn+=s_["fn"]
            P = tp/(tp+fp) if tp+fp else 0; Rc = tp/(tp+fn) if tp+fn else 0
            sweep[f"{T}|{W}"] = dict(P=P, R=Rc, F1=2*P*Rc/(P+Rc) if P+Rc else 0)
    # throughput
    ev = gen("Campus", 0)[0]; ev = ev*5; ev.sort(key=lambda e: e[1])
    t=time.perf_counter(); run(ev, *build("NetGuard (full)")); dt=time.perf_counter()-t
    thr = dict(events=len(ev), seconds=dt, eps=len(ev)/dt)
    json.dump(dict(summary=summ, stats=stats, byrate=byrate, sweep=sweep, thr=thr), open(RES / "results.json", "w"), indent=1)
    print(json.dumps(dict(summary=summ["Hostel"]["NetGuard (full)"], byrate=byrate, thr=thr), indent=1))
