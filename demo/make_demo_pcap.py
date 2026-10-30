"""Builds demo/demo.pcap: a 3-minute capture of a small network with benign traffic and two attacks.

Timeline (seconds):
   0-180  normal browsing by 5 hosts, periodic ARP refreshes
   40     a laptop replaces its network card (ONE legitimate MAC change)       -> no alert expected
   55     passive-FTP-like burst: 6 connections to one server                   -> no alert expected
   70     fast SYN scan of 10.0.0.20 (100 ports, 50 packets/s)                  -> PORT_SCAN
   110-130 ARP spoofing of the gateway 10.0.0.1 by 10.0.0.66                     -> ARP_SPOOF
   150    slow SYN scan of 10.0.0.20 (2 packets/s, 60 ports)                    -> PORT_SCAN
Run:  python3 netguard.py --pcap demo/demo.pcap --gateway 10.0.0.1
"""
import pathlib, random
from scapy.all import ARP, IP, TCP, Ether, wrpcap

r = random.Random(7)
GW, GW_MAC = "10.0.0.1", "aa:aa:aa:aa:aa:01"
hosts = {f"10.0.0.{i}": f"aa:aa:aa:aa:aa:{i:02x}" for i in (10, 11, 12, 13, 14)}
ATTACKER, ATT_MAC = "10.0.0.66", "bb:bb:bb:bb:bb:66"
pk = []


def add(t, p):
    p.time = 1_760_000_000.0 + t
    pk.append(p)


def arp(t, ip, mac):
    add(t, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=mac, pdst=ip))


def syn(t, src, dst, port, mac="aa:aa:aa:aa:aa:00"):
    add(t, Ether(src=mac) / IP(src=src, dst=dst) / TCP(sport=r.randrange(1024, 60000), dport=port, flags="S"))


# benign: ARP refreshes and web/DNS connections
for ip, mac in list(hosts.items()) + [(GW, GW_MAC)]:
    t = r.uniform(0, 5)
    while t < 180:
        arp(t, ip, mac if not (ip == "10.0.0.12" and t > 40) else "cc:cc:cc:cc:cc:12")   # NIC swap at t=40
        t += r.uniform(20, 40)
for ip, mac in hosts.items():
    t = r.uniform(0, 3)
    while t < 180:
        t += r.expovariate(0.8)
        syn(t, ip, f"93.184.{r.randrange(256)}.{r.randrange(256)}", r.choice([80, 443, 53]), mac)
arp(40.0, "10.0.0.12", "cc:cc:cc:cc:cc:12")
# benign burst to one server on a few ports (passive FTP-like)
for i, port in enumerate(r.sample(range(30000, 40000), 6)):
    syn(55 + i * 0.3, "10.0.0.13", "10.0.0.30", port, hosts["10.0.0.13"])
# attack 1: fast SYN scan
for i, port in enumerate(r.sample(range(1, 1025), 100)):
    syn(70 + i * 0.02, ATTACKER, "10.0.0.20", port, ATT_MAC)
# attack 2: ARP spoofing of the gateway (attacker poisons, gateway answers in between)
t = 110.0
while t < 130:
    arp(t, GW, ATT_MAC); arp(t + 0.8, GW, GW_MAC); t += 2.0
# attack 3: slow SYN scan
for i, port in enumerate(r.sample(range(1, 1025), 60)):
    syn(150 + i * 0.5, ATTACKER, "10.0.0.20", port, ATT_MAC)

pk.sort(key=lambda p: p.time)
out = pathlib.Path(__file__).with_name("demo.pcap")
wrpcap(str(out), pk)
print(f"wrote {out} ({len(pk)} packets)")
