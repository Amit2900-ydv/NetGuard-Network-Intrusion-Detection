"""Measures end-to-end packet-handling throughput of NetGuard (Scapy decoding + detection) on a synthetic capture."""
import sys, pathlib, random, time, io, contextlib, json, tempfile, os
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scapy.all import Ether, IP, TCP, ARP, wrpcap, rdpcap
from netguard import NetGuard, ArpDetector

r = random.Random(1); pk = []; t = 0.0
for i in range(20000):
    t += 0.002
    p = (Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=f"10.0.0.{r.randrange(2, 60)}", hwsrc="aa:bb:cc:dd:ee:%02x" % r.randrange(60))
         if i % 10 == 0 else
         Ether() / IP(src=f"10.0.1.{r.randrange(2, 60)}", dst="93.184.216.34") / TCP(sport=r.randrange(1024, 60000), dport=r.choice([80, 443, 53]), flags="S"))
    p.time = t; pk.append(p)
path = os.path.join(tempfile.gettempdir(), "netguard_bench.pcap"); wrpcap(path, pk)
pkts = rdpcap(path); ng = NetGuard(arp=ArpDetector(gateway_ip="10.0.0.1"), quiet=True)
t0 = time.perf_counter()
for p in pkts: ng.handle(p)
dt = time.perf_counter() - t0
print(f"{len(pkts)} packets in {dt:.2f}s -> {len(pkts)/dt:,.0f} packets/s (Scapy decoding + detection)")
