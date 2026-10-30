import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                      # makes `import netguard` work from the repo root
RES, FIGS = ROOT / "results", ROOT / "docs" / "figures"
import json, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from evaluate import *
d = json.load(open(RES / "results.json")); S = d["summary"]
plt.rcParams.update({"font.size":9,"axes.spines.top":False,"axes.spines.right":False,"font.family":"DejaVu Sans"})
C = {"blue":"#0072B2","orange":"#E69F00","grey":"#7a7a7a","green":"#009E73"}
rates = SCAN_RATES; out = {}; evc = {}
for prof in PROFILES: evc[prof] = float(np.mean([len(gen(prof, s)[0]) for s in range(20)]))
for W in (10, 30, 60):
    hit = {r: [] for r in rates}; fpc = 0
    for prof in PROFILES:
        for s in range(20):
            ev, ae, se, hs = gen(prof, s)
            al = run(ev, ArpDetector(gateway_ip="10.0.0.1"), PortScanDetector(window=W, threshold=15))
            for (src, t0, t1, rate) in se: hit[rate].append(any(a[1]=="PORT_SCAN" and a[2]==src and t0<=a[0]<=t1+W for a in al))
            fpc += score(al, ae, se, len(hs)+1, W=W)["PORT_SCAN"]["fp"]
    out[W] = dict(recall={str(r): float(np.mean(v)) for r, v in hit.items()}, fp=fpc)
d["window_rate"] = out; d["events"] = evc; json.dump(d, open(RES / "results.json","w"), indent=1); print(out, evc)

fig, ax = plt.subplots(figsize=(7.2, 1.7)); ax.axis("off"); ax.set_xlim(0,100); ax.set_ylim(0,32)
boxes = [(1,"Network\ntraffic\n(LAN / pcap)",C["grey"],16),(21,"Packet capture\n(Scapy sniff)",C["blue"],19),(45,"Detection engine",C["blue"],26),(78,"Alert module\n(console, log,\nTelegram Bot API)",C["orange"],21)]
for x,t,c,w in boxes:
    ax.add_patch(FancyBboxPatch((x,9),w,14,boxstyle="round,pad=0.3,rounding_size=1.2",fc="white",ec=c,lw=1.6)); ax.text(x+w/2,16,t,ha="center",va="center",fontsize=8)
for a,b in ((17,21),(40,45),(71,78)): ax.annotate("",xy=(b,16),xytext=(a,16),arrowprops=dict(arrowstyle="-|>",color="#333",lw=1.2))
ax.text(58,28.5,"ARP monitor: IP$\\to$MAC table,\ngateway pinning, $k$ changes in $W$ s",ha="center",fontsize=7.2,color="#333")
ax.text(58,2.2,"Scan analyser: distinct ports per (src, dst)\nSYN-only, sliding window $W$, threshold $T$",ha="center",fontsize=7.2,color="#333")
fig.savefig(str(FIGS / "fig_arch.pdf"), bbox_inches="tight"); plt.close()

fig, axs = plt.subplots(1,2,figsize=(7.2,2.25),sharey=True)
for ax,kind,tt in zip(axs,("ARP_SPOOF","PORT_SCAN"),("ARP spoofing","Port scanning")):
    x = np.arange(3)
    for j,(cfg,col,lab,h) in enumerate((("Naive (any MAC change / cumulative ports)",C["grey"],"Naive baseline",""),("NetGuard (full)",C["blue"],"NetGuard","//"))):
        v = [S[p][cfg][kind]["f1_mean"] for p in PROFILES]; sd = [S[p][cfg][kind]["f1_sd"] for p in PROFILES]
        ax.bar(x+(j-.5)*.36,v,.34,color=col,label=lab,hatch=h,edgecolor="white",yerr=sd,ecolor="#333",capsize=2,lw=0)
    ax.set_xticks(x); ax.set_xticklabels(list(PROFILES)); ax.set_title(tt,fontsize=9); ax.set_ylim(0,1.12)
axs[0].set_ylabel("F1 (mean $\\pm$ SD, 20 seeds)"); axs[1].legend(frameon=False,fontsize=8,loc="upper right")
fig.tight_layout(); fig.savefig(str(FIGS / "fig_f1.pdf")); plt.close()

fig, (axa, axb) = plt.subplots(1,2,figsize=(7.2,2.3))
for W,col,mk in ((10,C["blue"],"o"),(30,C["orange"],"s"),(60,C["green"],"^")):
    axa.plot(range(4),[out[W]["recall"][str(r)] for r in rates],marker=mk,color=col,lw=1.6,ms=5,label=f"$W_s$ = {W} s")
axa.set_xticks(range(4)); axa.set_xticklabels([f"{r:g}" for r in rates]); axa.set_xlabel("Scan rate (packets/s)"); axa.set_ylabel("Scan recall"); axa.set_ylim(-.03,1.1); axa.legend(frameon=False,fontsize=7.5,loc="center right"); axa.set_title("(a) Recall vs scan rate",fontsize=9)
Ts=[5,10,15,20,30,50]
for W,col,mk in ((5,C["grey"],"v"),(10,C["blue"],"o"),(30,C["orange"],"s")):
    axb.plot(range(6),[d["sweep"][f"{T_}|{W}"]["F1"] for T_ in Ts],marker=mk,color=col,lw=1.6,ms=5,label=f"$W_s$ = {W} s")
axb.set_xticks(range(6)); axb.set_xticklabels(Ts); axb.set_xlabel("Threshold $T$ (distinct ports)"); axb.set_ylabel("Scan F1 (Hostel)"); axb.set_ylim(.55,1.03); axb.legend(frameon=False,fontsize=7.5,loc="lower center"); axb.set_title("(b) F1 vs threshold",fontsize=9)
fig.tight_layout(); fig.savefig(str(FIGS / "fig_rate.pdf")); plt.close()

cfgs = ["NetGuard (full)","- gateway rule","- windowed change rule","- time window","- SYN-only filter","- per-destination grouping","k=1 (single change)","Naive (any MAC change / cumulative ports)"]
lab = ["Full","$-$gate-\nway pin","$-$window\nrule","$-$time\nwindow","$-$SYN\nfilter","$-$per-dst\ngroup","$k{=}1$","Naive"]
fig, axs = plt.subplots(1,2,figsize=(7.2,2.25),sharey=True)
for ax,kind,tt in zip(axs,("ARP_SPOOF","PORT_SCAN"),("ARP spoofing","Port scanning")):
    v = [np.mean([S[p][c][kind]["f1_mean"] for p in PROFILES]) for c in cfgs]
    ax.bar(range(8),v,color=[C["blue"]]+[C["orange"]]*6+[C["grey"]],edgecolor="white")
    for i,x in enumerate(v): ax.text(i,x+.02,f"{x:.2f}",ha="center",fontsize=7)
    ax.set_xticks(range(8)); ax.set_xticklabels(lab,fontsize=6); ax.set_title(tt,fontsize=9); ax.set_ylim(0,1.15)
axs[0].set_ylabel("Mean F1 (3 profiles)"); fig.tight_layout(); fig.savefig(str(FIGS / "fig_ablation.pdf")); plt.close()
