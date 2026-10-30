# How NetGuard works

## The two attacks

**ARP spoofing.** ARP maps an IPv4 address to a MAC address inside one subnet. It has no authentication:
a host accepts an ARP reply even if it never asked, and a newer reply overwrites the older cache entry.
An attacker who keeps claiming the gateway's IP with its own MAC becomes a man-in-the-middle.

**Port scanning.** Before attacking, an attacker probes many ports of a target (e.g. `nmap -sS`) to find open
services. Each probe is a TCP segment with the SYN flag set and ACK clear.

## Detection rules

| Detector | Rule | Default |
|---|---|---|
| ARP – windowed change rule | the MAC bound to one IP changes **k** times within **W_a** seconds | k = 2, W_a = 10 s |
| ARP – gateway pinning | the first MAC seen for the gateway is trusted; any other MAC claiming it alerts immediately | `--gateway IP` |
| Port scan | **T** distinct ports of **one destination** probed by one source within **W_s** seconds (SYN-only segments) | T = 15, W_s = 10 s |
| Both | after an alert for a key, repeats are suppressed for one window (cool-down) | = window |

### Why these design choices (found with the ablation study in `experiments/`)

* **Tolerate one MAC change (k = 2).** A replaced network card or a DHCP re-lease changes a binding once. With k = 1
  the false-alarm precision falls to 0.19 on our synthetic traffic.
* **Group scans per destination.** Counting distinct (destination, port) pairs per source makes every browsing host
  look like a scanner (scan F1 fell from 0.86 to 0.04–0.73).
* **Count only SYN-only segments.** ACK segments of established flows add distinct ports and cause false alarms.
* **Use a sliding window.** A cumulative counter eventually flags every active host.
* **Gateway pinning** mainly shortens detection latency (0.3–0.7 s versus 0.8–1.3 s); it is not essential for F1.

### Detectability of slow scans

A scan sending distinct ports at rate λ puts λ·W_s ports in a window, so it is reliably detected only if
λ ≳ T / W_s (1.5 packets/s for the defaults) and the expected detection delay is about T/λ. A scan at 0.5 packets/s
is therefore almost invisible with W_s = 10 s (recall 5.8 %) but fully detected with W_s = 30 s.
If the probe times are Poisson, the chance that one window reaches the threshold is
`P(N >= T) = 1 - sum_{i<T} exp(-λW)(λW)^i / i!`.

## Where to run it

NetGuard is passive. On a switched network a host sees broadcast frames and frames addressed to itself, so run it
on the victim, on the gateway, or on a host that receives mirrored traffic (SPAN port). A forged *unicast* ARP reply
sent to another station is invisible to it.

## Complexity

O(1) amortised work per packet (every timestamp enters and leaves its queue once); memory is
O(tracked hosts + packets inside one window).
