"""Unit tests for the two detectors (pure Python, no packets needed)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netguard import ArpDetector, PortScanDetector

GW, GW_MAC, EVIL = "10.0.0.1", "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:99"


# ---------------- ARP ----------------
def test_arp_first_sight_is_not_an_alert():
    d = ArpDetector(gateway_ip=GW)
    assert d.process(0, "10.0.0.7", "aa:aa:aa:aa:aa:07") is None


def test_arp_single_mac_change_is_tolerated():
    """A replaced NIC / DHCP re-lease changes the binding once: no alert."""
    d = ArpDetector(gateway_ip=GW)
    d.process(0, "10.0.0.7", "aa:aa:aa:aa:aa:07")
    assert d.process(5, "10.0.0.7", "cc:cc:cc:cc:cc:07") is None
    assert d.process(100, "10.0.0.7", "cc:cc:cc:cc:cc:07") is None


def test_arp_two_changes_within_window_alert():
    d = ArpDetector(gateway_ip=GW)
    d.process(0, "10.0.0.7", "aa:aa:aa:aa:aa:07")
    assert d.process(1, "10.0.0.7", EVIL) is None                  # attacker claims the IP
    alert = d.process(2, "10.0.0.7", "aa:aa:aa:aa:aa:07")          # owner refreshes -> flip-flop
    assert alert and alert[0] == "ARP_SPOOF" and alert[1] == "10.0.0.7"


def test_arp_changes_far_apart_do_not_alert():
    """Two legitimate changes more than W seconds apart (Wi-Fi <-> Ethernet) are fine."""
    d = ArpDetector(gateway_ip=GW, window=10)
    d.process(0, "10.0.0.7", "aa:aa:aa:aa:aa:07")
    assert d.process(60, "10.0.0.7", "cc:cc:cc:cc:cc:07") is None
    assert d.process(130, "10.0.0.7", "aa:aa:aa:aa:aa:07") is None


def test_arp_gateway_pinning_alerts_immediately():
    d = ArpDetector(gateway_ip=GW)
    d.process(0, GW, GW_MAC)
    alert = d.process(1, GW, EVIL)
    assert alert and alert[0] == "ARP_SPOOF" and EVIL in alert[2] and GW_MAC in alert[2]


def test_arp_gateway_restoration_does_not_alert_again():
    d = ArpDetector(gateway_ip=GW, cooldown=0)
    d.process(0, GW, GW_MAC)
    assert d.process(1, GW, EVIL) is not None
    assert d.process(2, GW, GW_MAC) is None                         # trusted MAC is back


def test_arp_cooldown_suppresses_repeats():
    d = ArpDetector(gateway_ip=GW, window=10)
    d.process(0, GW, GW_MAC)
    assert d.process(1, GW, EVIL) is not None
    assert d.process(2, GW, GW_MAC) is None
    assert d.process(3, GW, EVIL) is None                           # inside the 10 s cool-down
    assert d.process(20, GW, EVIL) is not None                      # cool-down over


def test_arp_without_gateway_option_still_uses_window_rule():
    d = ArpDetector(use_gateway=False)
    d.process(0, GW, GW_MAC)
    d.process(1, GW, EVIL)
    assert d.process(2, GW, GW_MAC) is not None


# ---------------- port scan ----------------
def _scan(d, src, dst, ports, t0=0.0, step=0.1, syn=True):
    out = []
    for i, p in enumerate(ports):
        a = d.process(t0 + i * step, src, dst, p, is_syn=syn)
        if a: out.append(a)
    return out


def test_scan_of_many_ports_on_one_host_alerts():
    d = PortScanDetector(threshold=15, window=10)
    alerts = _scan(d, "10.0.9.9", "10.0.0.5", range(1000, 1030))
    assert len(alerts) == 1 and alerts[0][0] == "PORT_SCAN" and alerts[0][1] == "10.0.9.9"


def test_browsing_many_servers_is_not_a_scan():
    """Same port on many different servers (web browsing) must not alert."""
    d = PortScanDetector(threshold=15, window=10)
    alerts = [d.process(i * 0.1, "10.0.0.7", f"93.184.{i}.1", 443) for i in range(200)]
    assert not any(alerts)


def test_ack_only_segments_are_ignored():
    d = PortScanDetector(threshold=15, window=10)
    assert not _scan(d, "10.0.0.7", "10.0.0.1", range(2000, 2100), syn=False)


def test_slow_probing_below_rate_does_not_alert():
    """One probe every 2 s: only 5 ports fit in a 10 s window (< 15)."""
    d = PortScanDetector(threshold=15, window=10)
    assert not _scan(d, "10.0.9.9", "10.0.0.5", range(1000, 1060), step=2.0)


def test_longer_window_catches_the_slow_scan():
    d = PortScanDetector(threshold=15, window=60)
    assert _scan(d, "10.0.9.9", "10.0.0.5", range(1000, 1060), step=2.0)


def test_repeated_probes_of_same_port_count_once():
    d = PortScanDetector(threshold=15, window=10)
    assert not _scan(d, "10.0.9.9", "10.0.0.5", [80] * 100)


def test_scan_alert_cooldown():
    d = PortScanDetector(threshold=15, window=10)
    assert len(_scan(d, "10.0.9.9", "10.0.0.5", range(1000, 1100), step=0.05)) == 1   # 5 s scan -> 1 alert
