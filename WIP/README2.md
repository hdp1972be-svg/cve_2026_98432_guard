
# CVE-2026-98432 XDP Guard
# 

A temporary eBPF/XDP mitigation for **CVE-2026-98432**, a TCP/IPv4-options
processing bug. The guard inspects packets at the XDP hook, drops IPv4/TCP
packets that carry IPv4 options (IHL > 5), and passes everything else
unmodified. Whitelisting allows trusted sources (exact IP or /24 prefix) to
bypass the drop, and a runtime "wake" flag allows operators to disable
enforcement without detaching the program.

The implementation is designed to build and run **on Linux 4.18 through 6.x**
without kernel source at build time, and to log every meaningful event to
**systemd-journald**.

Beyond the mitigation itself, the guard gives you **source-level visibility**
into exploit attempts: every dropped packet is counted per source, logged to
journald with the offending source IP, and exposed via `mtcp-guard-ctl
drop-ips`. This turns the mitigation into an active-detection sensor — you
learn **who** is sending CVE-2026-98432-shaped traffic to your host, in real
time.

---

## Table of contents

1. [Components](#components)
2. [Repository layout](#repository-layout)
3. [Requirements](#requirements)
4. [Quick start](#quick-start)
5. [Build](#build)
6. [Install and attach](#install-and-attach)
7. [Operating the guard](#operating-the-guard)
8. [Daemon](#daemon)
9. [Journald logging](#journald-logging)
10. [Data model](#data-model)
11. [Validation matrix](#validation-matrix)
12. [Diagnostics and recovery](#diagnostics-and-recovery)
13. [Compatibility notes](#compatibility-notes)
14. [Security model](#security-model)
15. [Known limitations](#known-limitations)
16. [Uninstall](#uninstall)

---

## Components

| Component | Language | Purpose |
|---|---|---|
| `cve_2026_98432_guard.c` | C (BPF) | XDP program: parse Ethernet + VLAN + IPv4 + options, drop or pass, update maps, emit perf events |
| `mtcp-guard-ctl.c` | C | Userspace CLI: stats, drop-ips, wake, whitelist add/remove/list/load/save |
| `mtcp-guardd.c` | C | Userspace daemon: consumes perf event map, logs every drop to journald, SIGHUP-driven whitelist reload |
| `xdp_option_probe.c` | C | Raw Ethernet frame generator: sends a TCP/SYN packet with a Record Route option, used to prove the datapath |
| `install` | Shell | Deploys the object, loads it, pins all maps (shape-verified), attaches to interfaces |
| `remove` | Shell | Stops the daemon, detaches XDP, unpins maps and program |
| `build.sh` | Shell | Kernel-aware build: autodetects target, selects map ABI and perf helper ID, compiles all four binaries |
| `check-bpf-support` | Shell | Pre-flight: kernel config, bpffs, bpftool, XDP generic mode |
| `whitelist.conf` | Config | Persistent whitelist, loaded by the daemon at start and on SIGHUP |

---

## Repository layout

cve_2026_98432_guard.c eBPF program (no kernel headers required)
mtcp-guard-ctl.c CLI utility
mtcp-guardd.c journald-logging daemon
xdp_option_probe.c packet generator for testing
install deploy + load + pin + attach
remove stop + detach + unpin
build.sh build orchestrator
check-bpf-support kernel capability probe
whitelist.conf persistent whitelist (optional)
README.md this file

---

## Requirements

THIS NEEDS TO BE UPDATED TO THE ADDITIONAL HEADER LIBS

### Runtime

- Linux 4.18 or newer with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
  `CONFIG_NET`, `CONFIG_INET` enabled.
- A mounted bpffs at `/sys/fs/bpf`.
- `bpftool` (for install/remove).
- `ip` (from `iproute2`).
- `systemd-journald` running (present on all systemd hosts; used for
  daemon logs).
- The daemon needs one of:
  - `libsystemd` at runtime (direct journald path, preferred), or
  - `/dev/log` provided by `systemd-journald.socket` (syslog fallback).

### Build

- `clang` with BPF target (`clang -target bpf`). Tested with 10.0.
- `gcc` for userspace binaries.
- `libbpf` development package (`libbpf-dev` / `libbpf-devel`).
- `libelf` development package (`libelf-dev` / `elfutils-libelf-devel`).
- Optional: `libsystemd` development package (`libsystemd-dev` /
  `systemd-devel`). Without it, the daemon falls back to `syslog()`.

Debian/Ubuntu one-shot:

```bash
sudo apt install clang gcc libbpf-dev libelf-dev libsystemd-dev \
                 bpftool iproute2
```

RHEL/Fedora:

sudo dnf install clang gcc libbpf-devel elfutils-libelf-devel \
                 systemd-devel bpftool iproute
 
# 1. Build everything
./build

# 2. Deploy and attach
sudo ./install

# 3. Start the daemon
sudo ./mtcp-guardd -d

# 4. Confirm the guard is live
sudo ./mtcp-guard-ctl stats

# 5. Watch journald for drop events
journalctl -t mtcp-guardd -f

Build

build.sh autodetects the running kernel, picks the correct map ABI and
bpf_perf_event_output helper ID, and compiles all binaries.

./build

=== cve_2026_98432 XDP build ===
[INFO] Source directory: /home/user/mtcp_fix
[INFO] Kernel detection: no --kernel given, auto-detecting running kernel...
  · uname -r               -> 5.15.0-124-generic
[INFO] Target kernel:    5.15.0-124-generic (from auto-detect (uname -r))
[INFO] Parsed kernel:    major=5 minor=15
  ┌─────────────────────────────────────────────────────────────┐
  │ Resolved build configuration                                │
  ├─────────────────────────────────────────────────────────────┤
  │ Target kernel:       5.15.0-124-generic                     │
  │ Kernel source:       auto-detect (uname -r)                 │
  │ Map ABI:             BTF-style                              │
  │ Map ABI source:      auto (kernel >= 5.3)                   │
  │ perf_event_output ID: 25                                    │
  │ perf helper source:  auto (kernel >= 5.0)                   │
  └─────────────────────────────────────────────────────────────┘
...
[OK] BUILD SUCCESSFUL

Build options:

./build.sh --kernel 5.10           # cross-target a specific kernel
./build.sh --legacy-maps           # force struct bpf_map_def
./build.sh --btf-maps              # force BTF-style maps
./build.sh --perf-helper-id 25     # override perf_event_output ID
./build.sh --no-userspace          # eBPF object + probe only
./build.sh --help

How the two map ABIs are selected

    LEGACY_MAPS=1 (auto for kernel < 5.3): struct bpf_map_def layout,
    compatible with all kernels since 4.18.

    LEGACY_MAPS=0 (auto for kernel >= 5.3): BTF-style map definitions
    (__uint/__type), supported by modern libbpf and required by
    5.18+ / 6.x kernels.

How the perf helper ID is selected

The bpf_perf_event_output helper ID differs between kernel branches:
Kernel	Helper ID
< 5.0	26
>= 5.0	25

build.sh chooses based on the detected (or given) target kernel. It can
be overridden with --perf-helper-id or the
BPF_FUNC_PERF_EVENT_OUTPUT environment variable.

Install and attach
bash
sudo ./install

What install does, in order:

    Deploy. Copies the .o, install, mtcp-guardd, mtcp-guard-ctl,
    whitelist.conf, and any ancillary files into
    /etc/cve-2026-98432-guard/. Existing files are left alone if they are
    byte-identical.

    Mount bpffs at /sys/fs/bpf if it isn't mounted already.

    Load the program (or reuse an already-pinned one).

    Resolve the program ID from bpftool prog show (name match, with a
    pin-path fallback).

    Pin all six maps, each with shape verification: every map ID is
    checked against its expected (type, key_size, value_size, max_entries) tuple before pinning. A wrong map is refused with a
    specific error rather than silently bound to the wrong pin path.

    Attach to every non-loopback interface in generic XDP mode. It
    never overwrites an existing XDP attachment from another program.

    Print a summary with program ID, pin paths, per-interface results,
    and failure count.

Expected summary:

==============================================
       CVE-2026-98432 XDP GUARD
==============================================
Program ID       : 79
Program pin      : /sys/fs/bpf/cve_2026_98432_guard
Object           : /etc/cve-2026-98432-guard/cve_2026_98432_guard.o
Statistics map   : /sys/fs/bpf/cve_2026_98432_stats
Whitelist map    : /sys/fs/bpf/cve_2026_98432_whitelist
Whitelist bitmap : /sys/fs/bpf/cve_2026_98432_whitelist_bm
Drop IPs map     : /sys/fs/bpf/cve_2026_98432_drop_ips
Events map       : /sys/fs/bpf/cve_2026_98432_events
Config map       : /sys/fs/bpf/cve_2026_98432_config
New attachments  : 3
Already attached : 0
Other XDP        : 0
Failed           : 0
==============================================

Operating the guard

Statistics
bash

sudo ./mtcp-guard-ctl stats

--- XDP statistics (aggregated across 4 CPUs) ---
  key 0 (TCP/IP-options drops): 4
    cpu 0: 1
    cpu 2: 2
    cpu 3: 1
  key 1 (Malformed IPv4 pass): 0
  key 2 (Wake-mode bypasses): 2
    cpu 1: 2
    
    
key 0: packets dropped by the guard.

key 1: malformed/truncated IPv4 packets that were passed (for
visibility, not dropped).

key 2: packets that would have been dropped but were passed because
the wake flag was set.

Per-source drop counters

sudo ./mtcp-guard-ctl drop-ips

List the LRU contents: 
--- drop-IP counts ---
192.0.2.99: 4
203.0.113.5: 12

This is an LRU hash bounded at 4096 entries. Under a distributed flood,
the oldest entries are evicted — the counters are for observability, not
for auditing.
Whitelisting

Three forms:

# exact source IP
sudo ./mtcp-guard-ctl whitelist add 203.0.113.5

# /24 prefix (the entire subnet)
sudo ./mtcp-guard-ctl whitelist add 198.51.100.0/24

# list current entries
sudo ./mtcp-guard-ctl whitelist list

Removal mirrors addition:

sudo ./mtcp-guard-ctl whitelist remove 203.0.113.5
sudo ./mtcp-guard-ctl whitelist remove 198.51.100.0/24

Persistence across daemon restarts:

# save the current map state to the persistent file
sudo ./mtcp-guard-ctl whitelist save /etc/cve-2026-98432-guard/whitelist.conf

# load an explicit file into the maps (replaces current contents)
sudo ./mtcp-guard-ctl whitelist load /path/to/file

The daemon reads /etc/cve-2026-98432-guard/whitelist.conf at startup and
on every SIGHUP. The file format is one entry per line, # for comments:


# cve_2026_98432_guard whitelist
# One entry per line: IP or IP/24
198.51.100.0/24
203.0.113.5
192.168.1.50

Reload from the persistent file:

sudo kill -HUP "$(sudo cat /run/mtcp-guardd.pid)"

On SIGHUP the daemon clears both maps first, then inserts the file's
entries. The file is authoritative: entries removed from the file are
removed from the maps.
Wake mode

Operationally useful for "disable the guard for maintenance without
detaching it":

sudo ./mtcp-guard-ctl wake on     # matching packets are passed, not dropped
sudo ./mtcp-guard-ctl wake off    # back to dropping

The wake flag lives in the config map. When it's 1, the BPF program
increments key 2 (Wake-mode bypasses) and returns XDP_PASS instead of
dropping. No detach, no reload, no traffic interruption for whitelisted
sources.

Daemon

mtcp-guardd is the userspace consumer of the perf event map. Its job:

    Open the events map.

    Consume struct drop_event records via perf_buffer__poll.

    Log every drop to journald.

    Reload config and whitelist on SIGHUP.
    
Running: 
sudo ./mtcp-guardd         # foreground, logs to stdout (journald still captures)
sudo ./mtcp-guardd -d      # daemonize, log exclusively to journald

Signals:

    SIGHUP — reload config (wake flag) and whitelist from
    /etc/cve-2026-98432-guard/whitelist.conf.

    SIGTERM / SIGINT — clean shutdown. Removes PID file, closes
    maps, exits 0.

PID file: /run/mtcp-guardd.pid.
Startup sequence

mtcp-guardd starting (pid=..., daemonized=1)
config reload: wake=0
whitelist: reload from /etc/cve-2026-98432-guard/whitelist.conf: N added, 0 error(s)
mtcp-guardd ready

Per-event logging

Every dropped packet produces one line:

drop src_ip=192.0.2.99 source_total=1

source_total is the cumulative count for that source from the drop_ips
LRU map. There is no rate limiting: the daemon was designed so
operators see every drop. If journald's own global rate limit
(RateLimitIntervalSec in /etc/systemd/journald.conf) causes dropped
lines under flood, that's a system-wide setting to tune, not a daemon bug.
Error handling

Every error is checked and posted to journald with the specific cause:

config: cannot open /sys/fs/bpf/cve_2026_98432_config: No such file or directory
whitelist: /etc/cve-2026-98432-guard/whitelist.conf:2: invalid IP 'not-an-ip'
whitelist: /etc/cve-2026-98432-guard/whitelist.conf:3: only /24 supported, skipping '10.0.0.0/16'
whitelist: reload from /etc/cve-2026-98432-guard/whitelist.conf: 2 added, 2 error(s)
perf_buffer_poll: Interrupted system call

No error is swallowed, no line is silently skipped. journalctl -t mtcp-guardd is the definitive source of truth for daemon behavior.
Journald logging

All daemon logs go through sd_journal_print(3) when libsystemd is
linked, or syslog(3) when it isn't. On systemd hosts both routes land in
journald and are visible with:

journalctl -t mtcp-guardd --since '10 minutes ago' --no-pager
journalctl -t mtcp-guardd -f

If you install mtcp-guardd as a systemd unit, use journalctl -u mtcp-guardd instead.
Log volume control

Since every drop is logged, a real DoS produces thousands of lines per
second. Two knobs control this:

Daemon-side, in the unit file:

[Service]
LogRateLimitIntervalSec=30
LogRateLimitBurst=5000

System-side, in /etc/systemd/journald.conf:

RateLimitIntervalSec=30
RateLimitBurst=10000

Setting either to 0 disables journald's per-unit suppression entirely.
This is the correct way to bound log volume — the daemon deliberately does
not suppress events itself, so what's in the journal is what actually
happened.
Log rotation

Journald rotates by size and age; the default limits (typically 10% of
the disk, or a few GB) apply. If you need longer retention for security
auditing, configure SystemMaxUse= and SystemMaxFileSize= in
/etc/systemd/journald.conf.

Data model

Six pinned BPF maps, all under /sys/fs/bpf/:
Map	Type	Key	Value	Max	Purpose
stats	percpu_array	u32	u64	3	drop / malformed / wake counters
whitelist	hash	u32 (saddr)	u8	4096	exact source IP allowlist
whitelist_bm	hash	u32 (prefix24)	u8	4096	/24 allowlist
drop_ips	lru_hash	u32 (saddr)	u64	4096	per-source drop counter
events	perf_event_array	u32	u32	1024	perf ring to daemon
config	array	u32	u32	1	key 0 = wake flag

Key representation

ip->saddr in the BPF program is the raw packet bytes viewed as a
u32. On little-endian hosts that means the address's byte layout in
memory matches inet_pton's output. The ctl and the daemon both call
inet_pton and memcpy the resulting bytes into a u32, so their keys
are byte-identical to the BPF program's keys. No endian swap is needed —
the BPF side and userspace side agree on "raw saddr".

For /24 lookups:

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ip & 0x00ffffffU;
#else
    return ip & 0xffffff00U;
#endif

Both the BPF program and the ctl use this identical function, so prefix
keys match.
Map pinning

install shape-verifies each map ID before pinning it. The two
hash-shaped maps (whitelist and whitelist_bm) are indistinguishable by
shape alone, so they're disambiguated by ID order (smaller ID = earlier
declared). If the assignment ever flips on a specific libbpf version, the
ctl's /24 add → list test catches it immediately (see the validation
matrix).
Validation matrix

Everything below has been verified against real wire traffic on a kernel
5.15 host. Each row is a reproducible test you can run yourself.
Build & load
Test	Expected	Verified
./build on kernel 5.15	eBPF object, probe, daemon, ctl all built	✅
sudo ./install	program pinned, all 6 maps pinned, all interfaces attached	✅
bpftool net show	program ID attached on each interface	✅
find /sys/fs/bpf -name '*98432*'	7 entries (program + 6 maps)	✅
Datapath

Trigger traffic with the packet probe:

LO_MAC=$(cat /sys/class/net/lo/address)
sudo ./xdp_option_probe lo "$LO_MAC" 192.0.2.99 127.0.0.1 8080

Test	Command	Expected	Verified
Non-whitelisted source	probe with 192.0.2.99	key 0 +1, drop-ips +1	✅
Exact whitelist	whitelist add 192.0.2.99 then probe	no key 0 change, no drop-ips change	✅
/24 whitelist	whitelist add 192.0.2.0/24 then probe	no key 0 change	✅
Wake mode	wake on then probe	key 2 +1, no key 0 change	✅
Wake off	wake off then probe	key 0 +1 again	✅
Whitelist persistence
Test	Expected	Verified
Startup reload from whitelist.conf	entries loaded, correct sections	✅
SIGHUP with a smaller file	old entries cleared, new entries loaded	✅
SIGHUP with a malformed file	every error logged with file:line:cause, valid entries still loaded	✅
whitelist save / load round-trip	symmetric: saved state == loaded state	✅
whitelist add → save → daemon restart	new entries survive restart	✅
Daemon

Test	Expected	Verified
Startup	journald shows 4 lines (start, config, whitelist, ready)	✅
Drop event	journald shows drop src_ip=... source_total=N	✅
SIGHUP reload	journald shows received SIGHUP, reloading + counts	✅
Malformed whitelist on reload	journald shows per-line errors with file:line:cause	✅
SIGTERM shutdown	journald shows mtcp-guardd shutting down, PID file removed	✅
Diagnostics and recovery
The guard is not dropping packets

    Confirm the program is attached:
    
    sudo bpftool net show
    
    
        The interface where traffic should be inspected must list the program.

    Confirm the probe reaches the guard's interface. Sending on the same
    interface that has the guard attached does not necessarily hit the
    ingress hook — XDP sees ingress, and locally-generated traffic exits
    via egress. Use lo, a veth pair, or a second host.

    Confirm the packet matches the drop criteria:

        IPv4 (not IPv6, not ARP)

        protocol == TCP

        ihl > 5 (there are IPv4 options)

        source is not whitelisted

        wake flag is off

mtcp-guard-ctl stats returns "No such file or directory"

The pinned maps aren't at /sys/fs/bpf/cve_2026_98432_*. Diagnose:

sudo bpftool map show | grep 98432
sudo ls -la /sys/fs/bpf/

If the maps exist in the kernel but aren't pinned, that's a loader bug.
If they're not in the kernel at all, the program isn't loaded.
install refuses to pin a map

[-] map 74 shape mismatch for stats
     expected: percpu_array 4 8 3
     actual:   lru_hash 4 8 4096
     
     The map ID the installer is about to pin doesn't match the expected shape
for that name. This is the shape-verification safety net doing its job:
a wrong-map pin is worse than no pin. Either the object was changed
without updating the expected shapes in install, or libbpf assigned IDs
differently than expected. Check:

sudo bpftool prog show id <PROG_ID> | grep map_ids
sudo bpftool map show id <MAP_ID>

and update the EXPECT array in install if the object's map set changed
legitimately.
Whitelist entries land in the wrong section

If whitelist list shows an entry under /24 prefixes that was added as
an exact IP (or vice versa), the two hash maps are swapped. Fix by
swapping whitelist and whitelist_bm in the EXPECT array in install,
then:

sudo ./remove
sudo ./install

Daemon doesn't log drops

    Check the daemon is running: pgrep -x mtcp-guardd.

    Check it can open the events map: journalctl -t mtcp-guardd | grep -i events.

    Verify the guard is dropping: mtcp-guard-ctl stats shows key 0 > 0.

    If key 0 increments but journald shows no drop lines, the perf buffer
    isn't being consumed. Restart the daemon; if the map was re-pinned while
    the daemon held an old fd, the fd points at a dead map.

Clean slate

To fully reset the runtime state:

sudo ./remove

This detaches all XDP, unpins the program and all maps, stops the daemon,
and removes the PID file. It does not remove
/etc/cve-2026-98432-guard/ or any systemd units.
Compatibility notes
Supported kernels
Kernel range	Map ABI	Perf helper ID	Status
4.18 – 4.19	legacy	26	Build-tested
5.0 – 5.2	legacy	25	Build-tested
5.3 – 5.17	BTF	25	Fully validated (5.15)
5.18 – 6.x	BTF	25	Build-tested
What breaks where

    Bounded loops. The 4.18 verifier cannot handle loops at all. The
    BPF program expands VLAN parsing into two explicit if blocks instead
    of a loop. Do not reintroduce a loop.

    struct bpf_map_def. Deprecated in 5.18, removed in 6.1. Use the
    LEGACY_MAPS switch to select the correct ABI for the target kernel.

    BTF map definitions. Require libbpf to parse the object's BTF.
    Modern clang (>= 10) emits BTF for -target bpf. Build with -g
    (the build.sh does this automatically on the BTF path).

    Map name truncation. Kernels truncate map names to 16 characters in
    bpftool map show output. The two whitelist maps become indistinguishable
    in text output — this is why install uses shape-based identification,
    not name-based.

Cross-building

./build --kernel 4.19 --legacy-maps will produce an object loadable on
4.19 even when the build host is 6.x, because LEGACY_MAPS=1 avoids BTF
map definitions entirely. The reverse (--kernel 6.6 --btf-maps on an old
host) requires a clang that can emit BTF; the object will fail to load if
the target kernel lacks BTF map support.
Security model
What the guard protects against

Packets that match the drop criteria are dropped at the XDP hook, before
they hit the kernel stack's TCP/IP parsing. This is the mitigation goal for
CVE-2026-98432.
What it does not protect against

    Non-TCP packets with IPv4 options. Only TCP + IPv4-options is in
    scope, per the mitigation policy.

    Fragmented IPv4 packets. The BPF program does not defragment; it
    only inspects packets whose full IPv4 header (including options) is
    present in the linear data area. Fragments that don't carry the full
    header are passed unmodified. If the attack vector involves fragments,
    the mitigation as written is incomplete.

    Whitelist bypass. A whitelisted source can send the attack packet
    and it will be passed. The whitelist is the operator's responsibility.

    Wake mode. Setting wake on disables the drop path entirely.
    Operators should only enable it for controlled maintenance windows.

    XDP generic mode. The guard attaches in generic mode by default,
    which means the packet reaches the driver, is turned into an skb, and
    then XDP runs. That still prevents the packet from reaching the
    network stack, but it's slower than native XDP and doesn't give the
    driver's zero-copy path. If the interface's driver supports native XDP
    and the kernel is new enough, switch to xdpdrv mode by editing
    install — but validate first on a non-production interface.

Privileges

    install requires root (needs CAP_BPF, CAP_NET_ADMIN,
    CAP_SYS_ADMIN for bpffs mount).

    mtcp-guard-ctl requires root (needs CAP_BPF to open pinned maps).

    mtcp-guardd requires root (opens pinned maps, reads perf events).

    The BPF object is owned by root, mode 0644. Pinned maps are root-only.

No component runs unprivileged. This is inherent to eBPF — opening a
pinned map requires CAP_BPF on kernels that enforce it.
Known limitations

    Persistence across reboot. All pinned objects live only for the
    lifetime of the running kernel. A reboot clears the BPF program, all six
    maps, and the daemon. Persistence requires systemd units (loader + daemon),
    which are outside the current scope of this README.

    Single-object design. All six maps belong to one program. Multiple
    programs sharing the same maps is a different architecture; it's not
    what this guard implements.

    No whitelist expiry. Whitelist entries persist until explicitly
    removed. There's no TTL or automatic reaper. This is intentional:
    operators expect whitelists to be stable across restarts.

    LRU drop-ips map. Under a distributed flood large enough to cycle
    the map (4096 entries), the oldest drop counters are evicted. This is a
    feature (bounded memory) but means drop-ips is not a complete audit
    log. The journald drop lines are the audit log; the LRU map is for
    live statistics.

    Rate-limited journald ingestion. The daemon logs every drop, but
    journald's own RateLimitIntervalSec / RateLimitBurst can suppress
    lines during a sustained flood. If you need absolute completeness, tune
    those settings or add a periodic-summary path (see Log volume control).
    
    Uninstall
    
    sudo ./remove
    
This:

    Stops mtcp-guardd.service if it exists.

    Detaches XDP from every interface that has the guard's program attached.

    Unpins the program and all six maps from /sys/fs/bpf/.

    Removes /run/mtcp-guardd.pid if present.

It intentionally leaves:

    /etc/cve-2026-98432-guard/ (the deployed binaries and whitelist.conf)

    Any systemd unit files installed outside this script

To remove those as well:
bash

sudo rm -rf /etc/cve-2026-98432-guard/
# and remove the relevant .service files if you installed them

A full reboot will also clear any remaining BPF state regardless.

Disclaimer

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and non-infringement. In no event shall
the authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising
from, out of or in connection with the software or the use or other
dealings in the software.

This is a temporary mitigation, not a fix. It does not patch
CVE-2026-98432; it only reduces the attack surface by dropping a narrow
class of packets at the XDP hook. It is not a substitute for applying the
official vendor kernel update when one becomes available. Deploying it
should be treated as an emergency measure to buy time, and it should be
removed once the underlying vulnerability is patched.

The drop policy has known gaps (see "Security model" and "What it does
not protect against"). Do not assume complete protection. Test in a lab
before deploying on production interfaces. Review the whitelist regularly;
a stale or overly broad whitelist entry defeats the mitigation.
Buy me a coffee

If this mitigation helped you keep a system running, and you feel like
saying thanks:

₿ Bitcoin (BTC): bc1qexampleaddress0000000000000000000

Ξ Ethereum (ETH): 0x0000000000000000000000000000000000000000

Monero (XMR): 4exampleexampleexampleexampleexampleexampleexample

Ko-fi / GitHub Sponsors: see repository sidebar

No obligation, no expectation — this was written to be useful, and it is
useful whether or not anyone sends anything. But if you do, the next
coffee gets a good review.

License

GPL-2.0. The eBPF program and userspace tools share the GPL license
because the eBPF program uses GPL-only helpers (bpf_perf_event_output on
some kernels, bpf_probe_read on others).
