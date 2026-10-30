#!/usr/bin/env python3
"""NetGuard - a lightweight network intrusion detection system (NIDS).

Detects two attacks on a local network, in real time, using only passive observation:

  * ARP spoofing  - an attacker claims another host's IP address with its own MAC address.
  * Port scanning - a source probes many different ports of one destination in a short time.

Alerts are printed, optionally appended to a CSV file, and optionally pushed to a Telegram chat.

Usage
-----
  sudo python3 netguard.py --live --gateway 192.168.1.1            # live capture
  python3 netguard.py --pcap demo/demo.pcap --gateway 10.0.0.1     # analyse a capture file
  Telegram: set NETGUARD_TOKEN and NETGUARD_CHAT_ID, then add --telegram.

Only use NetGuard on networks you own or are authorised to monitor.
"""
import argparse
import csv
import os
import time
from collections import defaultdict, deque


class ArpDetector:
    """ARP spoofing detector.

    Rule 1 (windowed change rule): alert when the MAC address bound to an IP changes at
    least `changes` (k) times within `window` seconds. A single change is tolerated because
    it is the normal footprint of a replaced network card or a DHCP re-lease.

    Rule 2 (gateway pinning): the first MAC address seen for `gateway_ip` is trusted; any
    later claim of the gateway address by a different MAC raises an alert at once. A claim by
    the trusted MAC never alerts, so the restoration after an attack does not alarm again.

    After an alert for an address, further alerts for it are suppressed for `cooldown`
    seconds (default: the window length).
    """

    def __init__(self, window=10.0, changes=2, use_gateway=True, gateway_ip=None, cooldown=None):
        self.W, self.k = window, changes
        self.cd = window if cooldown is None else cooldown
        self.table = {}                       # ip -> most recently claimed mac
        self.hist = defaultdict(deque)        # ip -> timestamps of recent MAC changes
        self.gateway_ip = gateway_ip
        self.use_gateway = use_gateway
        self.trusted = None                   # first-seen MAC of the gateway
        self.alerted = {}                     # ip -> time of last alert

    def process(self, ts, ip, mac):
        """Feed one ARP claim (time, IP, MAC). Returns an alert tuple or None."""
        old = self.table.get(ip)
        if old is None:                       # first time this IP is seen
            self.table[ip] = mac
            return None
        if self.use_gateway and ip == self.gateway_ip:
            if self.trusted is None:
                self.trusted = old
            if mac != self.trusted and ts - self.alerted.get(ip, -1e9) > self.cd:
                self.alerted[ip] = ts
                self.table[ip] = mac
                return ("ARP_SPOOF", ip, f"gateway {ip} claimed by {mac}, trusted {self.trusted}")
            self.table[ip] = mac
            return None
        if old != mac:
            h = self.hist[ip]
            h.append(ts)
            while h and ts - h[0] > self.W:
                h.popleft()
            self.table[ip] = mac
            if len(h) >= self.k and ts - self.alerted.get(ip, -1e9) > self.cd:
                self.alerted[ip] = ts
                return ("ARP_SPOOF", ip, f"MAC of {ip} changed {old} -> {mac}")
        return None


class PortScanDetector:
    """Vertical port-scan detector.

    Counts the distinct destination ports that a source has probed on ONE destination within
    a sliding window of `window` seconds, using only connection-opening segments (SYN set,
    ACK clear). Alerts when the count reaches `threshold` (T).

    `syn_only` and `per_dst` exist so that the experiments can switch these design elements
    off (ablation study); keep the defaults for normal use.
    """

    def __init__(self, window=10.0, threshold=15, syn_only=True, per_dst=True, cooldown=None):
        self.W, self.T, self.syn_only, self.per_dst = window, threshold, syn_only, per_dst
        self.cd = window if cooldown is None else cooldown
        self.hist = defaultdict(deque)        # key -> deque[(time, port or (dst, port))]
        self.alerted = {}

    def process(self, ts, src, dst, dport, is_syn=True):
        """Feed one TCP segment. Returns an alert tuple or None."""
        if self.syn_only and not is_syn:
            return None
        key = (src, dst) if self.per_dst else src
        h = self.hist[key]
        h.append((ts, dport if self.per_dst else (dst, dport)))
        while h and ts - h[0][0] > self.W:
            h.popleft()
        uniq = len({x for _, x in h})
        if uniq >= self.T and ts - self.alerted.get(key, -1e9) > self.cd:
            self.alerted[key] = ts
            return ("PORT_SCAN", src, f"{uniq} distinct ports on {dst} in {self.W}s")
        return None


def send_telegram(msg):
    """Send `msg` through the Telegram Bot API. Returns True on success."""
    token, chat = os.getenv("NETGUARD_TOKEN"), os.getenv("NETGUARD_CHAT_ID")
    if not (token and chat):
        return False
    import requests
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                          data={"chat_id": chat, "text": msg}, timeout=5)
        return r.ok
    except requests.RequestException:
        return False


class NetGuard:
    """Glue: dispatches each captured packet to the right detector and delivers alerts."""

    def __init__(self, arp=None, scan=None, notify=False, log_path=None, quiet=False):
        self.arp = arp or ArpDetector()
        self.scan = scan or PortScanDetector()
        self.notify, self.quiet = notify, quiet
        self.alerts = []                      # (timestamp, type, source, description)
        self.log_path = log_path
        if log_path and not os.path.exists(log_path):
            with open(log_path, "w", newline="") as f:
                csv.writer(f).writerow(["time", "type", "source", "description"])

    def handle(self, pkt):
        from scapy.all import ARP, IP, TCP
        ts, a = float(pkt.time), None
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):           # who-has / is-at
            a = self.arp.process(ts, pkt[ARP].psrc, pkt[ARP].hwsrc)
        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            t = pkt[TCP]
            a = self.scan.process(ts, pkt[IP].src, pkt[IP].dst, t.dport,
                                  is_syn=(int(t.flags) & 0x12) == 0x02)
        if a:
            self._deliver(ts, a)

    def _deliver(self, ts, a):
        self.alerts.append((ts,) + a)
        msg = f"ALERT {a[0]} src={a[1]} {a[2]}"
        if not self.quiet:
            print(msg, flush=True)
        if self.log_path:
            with open(self.log_path, "a", newline="") as f:
                csv.writer(f).writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)), *a])
        if self.notify and not send_telegram("NetGuard: " + msg):
            print("warning: Telegram alert could not be sent (check NETGUARD_TOKEN / NETGUARD_CHAT_ID / network)")


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetGuard: lightweight NIDS (ARP spoofing + port scan)")
    ap.add_argument("--live", action="store_true", help="sniff live traffic (needs admin/root)")
    ap.add_argument("--iface", help="network interface for --live")
    ap.add_argument("--pcap", help="analyse a capture file instead of live traffic")
    ap.add_argument("--telegram", action="store_true", help="send alerts via Telegram (env NETGUARD_TOKEN, NETGUARD_CHAT_ID)")
    ap.add_argument("--log", metavar="FILE", help="append alerts to a CSV file")
    ap.add_argument("--gateway", help="IP of the default gateway (enables gateway pinning)")
    ap.add_argument("--k", type=int, default=2, help="ARP: MAC changes of one IP within the window that raise an alert (default 2)")
    ap.add_argument("--arp-window", type=float, default=10.0, help="ARP window W_a in seconds (default 10)")
    ap.add_argument("--threshold", type=int, default=15, help="scan: distinct ports on one destination that raise an alert (default 15)")
    ap.add_argument("--scan-window", type=float, default=10.0, help="scan window W_s in seconds (default 10)")
    a = ap.parse_args(argv)
    from scapy.all import rdpcap, sniff
    ng = NetGuard(arp=ArpDetector(window=a.arp_window, changes=a.k, use_gateway=bool(a.gateway), gateway_ip=a.gateway),
                  scan=PortScanDetector(window=a.scan_window, threshold=a.threshold),
                  notify=a.telegram, log_path=a.log)
    if a.pcap:
        for p in rdpcap(a.pcap):
            ng.handle(p)
        print(f"done: {len(ng.alerts)} alert(s)")
    elif a.live:
        print("NetGuard is watching the network... press Ctrl+C to stop")
        try:
            sniff(iface=a.iface, prn=ng.handle, store=False)
        except KeyboardInterrupt:
            print(f"\nstopped: {len(ng.alerts)} alert(s)")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
