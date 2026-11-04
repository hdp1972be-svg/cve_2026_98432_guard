
Performance testing XDP is where you validate that the mitigation isn't a bottleneck. The key numbers to establish:

    Baseline throughput without the guard.

    Throughput with the guard attached, on non-matching traffic (the fast path — everything that isn't IPv4/TCP-with-options).

    Throughput with the guard under attack (traffic that hits the drop path).

    CPU cost of the guard per packet.

The guard runs in generic XDP mode by default, which is important: generic XDP is the slowest XDP mode (it allocates an skb before running XDP). It still avoids the network stack for dropped packets, but it adds work for passed packets. For a temporary mitigation, that's fine. For performance you'd want native XDP (xdpdrv), which needs a driver that supports it and a kernel new enough. Let me give you the whole picture.
1. Establish baseline

Your box has three interfaces. Pick the one that's actually used — likely wlx000c4313decc (Wi-Fi, 192.168.0.206) since it's the only one with an IP and traffic.

First, confirm the guard is attached:
bash

sudo bpftool net show

You should see:
text

xdp:
enp2s0(...) generic id 79
wlp3s0(...) generic id 79
wlx000c4313decc(...) generic id 79

Then:
bash

# Baseline: detach the guard, measure
sudo ip link set dev wlx000c4313decc xdp off

# ... run perf test ...

iperf3 between this host and another on the LAN is the standard way. On the other host:
bash

iperf3 -s

On this host:
bash

iperf3 -c <other-host-ip> -t 30 -P 4

Note the resulting receiver and sender bandwidth. That's your baseline.

Then re-attach the guard and repeat:
bash

sudo ip link set dev wlx000c4313decc xdpgeneric pinned /sys/fs/bpf/cve_2026_98432_guard
iperf3 -c <other-host-ip> -t 30 -P 4

The difference between the two is the cost of generic XDP on passed traffic. On a modern kernel and modern NIC driver, generic XDP usually costs 5–15% of throughput. On Wi-Fi, expect a bit more because the driver stack does more work per packet.

If you don't have a second host, use lo:
bash

# baseline on lo (detach guard first)
iperf3 -c 127.0.0.1 -t 10 -P 4

# re-attach guard to lo
sudo ip link set dev lo xdpgeneric pinned /sys/fs/bpf/cve_2026_98432_guard

# with guard
iperf3 -c 127.0.0.1 -t 10 -P 4

Loopback numbers are unrealistic (no NIC), but the relative difference tells you the guard's cost.
2. Measure the drop path

The drop path is the interesting one — that's what the guard exists for. Generate matching traffic (IPv4/TCP with options) as fast as you can and see how many packets per second the guard handles.

pktgen is the tool for this on Linux:
bash

sudo modprobe pktgen

But pktgen runs on the sending host and drops at the receiver, so it doesn't exercise the guard on your host's ingress unless you run it on the other host. If you have a second Linux box, on it:
bash

# On the sender: blast 1 million TCP-with-options packets at your host
sudo pktgen -i eth0 -d <your-ip> -m <your-mac> -p 8080 \
    -s 60 -n 1000000 -t tcp -o \
    --ipg 0 --ipdst <your-ip> --ipsrc 192.0.2.99

Without pktgen handy, hping3 or scapy loops from the other host work for smaller tests:
python

# on another host
from scapy.all import IP, TCP, IPOption, send
from time import time

pkt = IP(dst="192.168.0.206", src="192.0.2.99",
        options=[IPOption(b'\x01')]) / TCP(dport=8080, flags="S")

count = 100000
start = time()
send(pkt, loop=1, count=count, inter=0, verbose=0)
elapsed = time() - start
print(f"{count/elapsed:.0f} packets/sec")

While the sender blasts, on this host:
bash

# Before: note the current key 0 value
sudo /etc/cve-2026-98432-guard/mtcp-guard-ctl stats

After the flood:
bash

sudo /etc/cve-2026-98432-guard/mtcp-guard-ctl stats

key 0 divided by seconds elapsed gives you the packets-per-second the guard actually processed. If it's much less than the sender's rate, the guard is dropping some of them because its own capacity is exceeded — but that's fine, the attack volume is capped, which is the point. What you're measuring is how much the guard can handle before it becomes the bottleneck.

On a modern CPU in generic XDP mode, one core can typically process 1–2 million packets/sec through an XDP drop path. In native XDP mode, 5–10 million. The limiting factor on Wi-Fi is usually the driver itself, not the XDP program.
3. Measure the fast path

The most important number for a mitigation is: how much does the guard cost for the 99.99% of traffic that doesn't match the drop criteria?

That's the iperf3 test above. The fast path does:
c

// eth header check: ~4 bytes read
// VLAN loop: 0-2 iterations, byte reads
// IPv4 header check: 1-byte read (version + ihl)
// protocol check: 1-byte read
// total: ~10 bytes read, 4 branches, then XDP_PASS

The guard's cost on non-matching traffic is on the order of 1–2% of throughput. That's the number worth measuring, and iperf3 gives it directly.

If you see more than 5% degradation on iperf3, something is wrong:

    wake flag stuck on: check mtcp-guard-ctl wake off.

    The drop_ips LRU is being hit even on pass traffic: that would be a bug in the BPF program's control flow. Not present in the current code — the LRU update is inside if (is_whitelisted(...) == 0 && wake == 0).

    The whitelist maps are saturated: with 4096 entries, hash lookup is fast, but populating them heavily slows the lookup. Not a concern at 4096.

    Generic XDP mode active when native is available: the biggest single factor.

4. Check if native XDP is possible
bash

# Which mode is the guard attached in?
sudo bpftool net show | grep xdp

# Does the driver support native XDP?
sudo bpftool feature probe | grep -E 'native|driver'

# Or, per-interface:
ethtool -i wlx000c4313decc   # get driver name

If the driver supports native XDP (most modern Ethernet drivers do: ixgbe, i40e, mlx5, ice, bnxt, ena; Wi-Fi drivers mostly don't), you can attach with xdpdrv instead of xdpgeneric:
bash

# Detach generic
sudo ip link set dev enp2s0 xdp off

# Attach native (much faster)
sudo ip link set dev enp2s0 xdpdrv pinned /sys/fs/bpf/cve_2026_98432_guard

Check ethtool -i <iface> for the driver. If it's ath11k, ath10k, iwlwifi, mt7921, or similar Wi-Fi driver — native XDP is almost certainly unavailable. Those drivers don't support the XDP hook, and the interface will refuse xdpdrv, falling back to generic (or failing).

For Ethernet, xdpdrv is the mode you want.

install currently attaches with xdpgeneric. To make it use xdpdrv when the driver supports it:
bash

# In install, replace:
if ip link set dev "$iface" xdpgeneric pinned "$PROG_PIN"; then

# With a detection:
if ethtool -i "$iface" 2>/dev/null | grep -qE '^driver: (ixgbe|i40e|ice|mlx5_core|bnxt_en|ena)'; then
    mode=xdpdrv
else
    mode=xdpgeneric
fi
if ip link set dev "$iface" "$mode" pinned "$PROG_PIN"; then
    info "$iface: attached successfully ($mode)"

But that's a per-driver list and needs maintaining. The simpler criterion: try xdpdrv first, fall back to xdpgeneric on failure:
bash

if ip link set dev "$iface" xdpdrv pinned "$PROG_PIN" 2>/dev/null; then
    info "$iface: attached successfully (xdpdrv)"
elif ip link set dev "$iface" xdpgeneric pinned "$PROG_PIN"; then
    info "$iface: attached successfully (xdpgeneric)"
else
    error "$iface: attachment failed"
    ((failed+=1))
fi

That's the correct behavior: use the fastest mode that works on each interface.
5. Continuous measurement with stats

While the guard is live, watch the per-CPU stats to see load distribution:
bash

watch -n 1 'sudo /etc/cve-2026-98432-guard/mtcp-guard-ctl stats'

Under load, all four CPUs should show nonzero key 0 values if the XDP hook is running on multiple CPUs. If only one CPU shows activity, either:

    RSS is not distributing: single-queue NIC, or misconfigured interrupt affinity. Fix: ethtool -L <iface> combined <n> to enable multiple queues.

    The traffic is single-flow: one TCP flow goes to one queue, one CPU. That's expected for a single attacker. A real DoS has thousands of flows, which spread across queues.

Per-CPU distribution also matters for the per-CPU map: each CPU has its own slice of the map, so 4 CPUs with 1M drops each = 4M total. If you see only one CPU at 1M and the others at zero, that's single-queue RSS, and the guard is still processing 1M packets/sec — the ceiling is that one CPU.
6. Expected numbers
