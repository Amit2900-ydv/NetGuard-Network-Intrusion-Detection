"""End-to-end test: build a capture with Scapy, run it through NetGuard.handle()."""
import csv, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scapy.all import ARP, IP, TCP, Ether, rdpcap, wrpcap
from netguard import ArpDetector, NetGuard, main

GW, GW_MAC, EVIL = "10.0.0.1", "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:99"


def build(path):
    pk, t = [], [1000.0]

    def add(p, dt=0.1):
        t[0] += dt; p.time = t[0]; pk.append(p)
    add(Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GW, hwsrc=GW_MAC))
    for i in range(1, 31):                                           # SYN scan
        add(Ether() / IP(src="10.0.9.9", dst="10.0.0.5") / TCP(sport=4444, dport=1000 + i, flags="S"))
    add(Ether(src=EVIL, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GW, hwsrc=EVIL), dt=1.0)   # spoof
    for i in range(20):                                              # benign ACK traffic
        add(Ether() / IP(src="10.0.0.7", dst=GW) / TCP(sport=5000, dport=2000 + i, flags="A"))
    wrpcap(path, pk)


def test_pcap_round_trip(tmp_path):
    path = str(tmp_path / "t.pcap"); build(path)
    ng = NetGuard(arp=ArpDetector(gateway_ip=GW), quiet=True)
    for p in rdpcap(path): ng.handle(p)
    assert sorted(a[1] for a in ng.alerts) == ["ARP_SPOOF", "PORT_SCAN"]


def test_cli_writes_csv_log(tmp_path, capsys):
    path, log = str(tmp_path / "t.pcap"), str(tmp_path / "alerts.csv"); build(path)
    main(["--pcap", path, "--gateway", GW, "--log", log])
    rows = list(csv.reader(open(log)))
    assert rows[0] == ["time", "type", "source", "description"] and len(rows) == 3
    assert "done: 2 alert(s)" in capsys.readouterr().out
