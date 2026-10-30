import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                      # makes `import netguard` work from the repo root
RES, FIGS = ROOT / "results", ROOT / "docs" / "figures"

import numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
C = {"blue":"#0072B2","orange":"#E69F00","grey":"#7a7a7a","green":"#009E73"}
plt.rcParams.update({"font.size":8.5,"axes.spines.top":False,"axes.spines.right":False,"font.family":"DejaVu Sans"})
# taxonomy
fig, ax = plt.subplots(figsize=(7.2, 2.5)); ax.axis("off"); ax.set_xlim(0,100); ax.set_ylim(-1,38)
def bx(x,y,w,h,t,c,fs=7.5): ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.2,rounding_size=0.8",fc="white",ec=c,lw=1.4,zorder=3)); ax.text(x+w/2,y+h/2,t,ha="center",va="center",fontsize=fs,zorder=4)
bx(36,32,28,5,"Network intrusion detection",C["grey"],8.5)
cols=[(1,"Signature / rule-based",C["blue"],["Snort, Bro/Zeek","ARP: active probes, DAI,\nstatic tables"]),
      (34,"Statistical / threshold",C["green"],["Threshold Random Walk\n(Jung et al.)","SPADE; coordinated\nscans (Gates)"]),
      (67,"Learning-based",C["orange"],["Shallow ML (surveys)","Deep nets, Kitsune\nautoencoders"])]
for x,t,c,items in cols:
    ax.plot([50,x+16],[32,26.5],color="#999",lw=.8,zorder=1); bx(x,21.5,32,5,t,c,8)
    ax.plot([x+16,x+16],[21.5,1],color="#ccc",lw=.8,zorder=1)
    for i,it in enumerate(items): bx(x+2,13.5-i*10.5,28,7,it,c,7)
fig.savefig(str(FIGS / "fig_taxonomy.pdf"), bbox_inches="tight"); plt.close()
# prominent works
fig = plt.figure(figsize=(7.2,2.5)); gs = fig.add_gridspec(1,2,width_ratios=[1,1.25],wspace=.18)
ax = fig.add_subplot(gs[0]); th0, th1, a, b = 0.8, 0.2, 0.01, 0.99
e1, e0 = np.log(b/a), np.log((1-b)/(1-a))
def walk(p, n, seed):
    r = np.random.default_rng(seed); L=[0.0]
    for _ in range(n):
        ok = r.random() < p; L.append(L[-1] + (np.log(th1/th0) if ok else np.log((1-th1)/(1-th0))))
        if L[-1] >= e1 or L[-1] <= e0: break
    return L
for s_,p_,c,l in ((3,0.8,"#009E73","benign host"),(5,0.2,"#D55E00","scanner")):
    L = walk(p_,40,s_); ax.plot(range(len(L)),L,marker="o",ms=3,lw=1.4,color=c,label=l)
ax.axhline(e1,color="#333",ls="--",lw=1); ax.axhline(e0,color="#333",ls="--",lw=1)
ax.text(.2,e1+.35,r"$\ln\eta_1$ (declare scanner)",fontsize=7); ax.text(.2,e0-1.0,r"$\ln\eta_0$ (declare benign)",fontsize=7)
ax.set_xlabel("Connection attempts observed"); ax.set_ylabel(r"$\ln\Lambda(Y_n)$"); ax.set_ylim(e0-2,e1+2); ax.legend(frameon=False,fontsize=7.5,loc="center right"); ax.set_title("(a) Threshold random walk",fontsize=9)
ax2 = fig.add_subplot(gs[1]); ax2.axis("off"); ax2.set_xlim(0,100); ax2.set_ylim(0,40); ax2.set_title("(b) Kitsune pipeline",fontsize=9)
def bx2(x,y,w,h,t,c="#0072B2"): ax2.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.3,rounding_size=1",fc="white",ec=c,lw=1.3)); ax2.text(x+w/2,y+h/2,t,ha="center",va="center",fontsize=7)
bx2(1,15,17,10,"Raw\npacket","#7a7a7a"); bx2(24,15,18,10,"Feature\nextractor"); bx2(48,15,16,10,"Feature\nmapper")
for i,y in enumerate((29,20.5,12,3.5)): bx2(70,y-1,15,6.5,f"AE {i+1}" if i<3 else "AE $k$","#E69F00")
bx2(88,15,11,10,"Output\nAE","#009E73")
for x0,x1 in ((18,24),(42,48),(64,70)): ax2.annotate("",xy=(x1,20),xytext=(x0,20),arrowprops=dict(arrowstyle="-|>",lw=1,color="#333"))
ax2.annotate("",xy=(88,20),xytext=(85,20),arrowprops=dict(arrowstyle="-|>",lw=1,color="#333"))
ax2.text(93.5,10.5,"RMSE\nscore",ha="center",fontsize=7)
fig.savefig(str(FIGS / "fig_prominent.pdf"),bbox_inches="tight"); plt.close()
