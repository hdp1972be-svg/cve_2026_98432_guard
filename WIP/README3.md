# CVE-2026-98432 XDP Guard

A runtime mitigation, detection sensor and forensic capture tool for
CVE-2026-98432, the Linux kernel IPv4/TCP options vulnerability. It runs
as an XDP program at the earliest packet-processing hook, drops offending
packets before the kernel stack sees them, logs every drop to journald,
and writes the exact bytes to a pcap that opens in Wireshark.

It is designed for the case where the kernel cannot be rebuilt or patched
right now — embedded systems, appliances, industrial control, end-of-life
kernels, air-gapped hosts, distributed fleets. For hosts that can take the
vendor kernel patch this week, the patch is the right answer. This is for
the rest.

---

## What it does

**Mitigation.** Drops IPv4/TCP packets carrying IPv4 options (IHL > 5) at
the XDP hook, before the kernel allocates an skb. The vulnerable parser
never sees the packet. Works on kernels 4.18 through 6.x, with native XDP
(`xdpdrv`) where the driver supports it and generic XDP (`xdpgeneric`)
everywhere else.

**Detection.** Every drop is counted per source IP in an LRU map and
logged to journald with the source address, the ingress interface name,
and the capture length. `mtcp-guard-ctl stats` shows per-CPU aggregated
drop / malformed / wake-bypass counters. `mtcp-guard-ctl drop-ips` shows
the current top offenders. A whitelist (exact IP or `/24`) lets operators
carve out legitimate sources that use IPv4 options for real reasons —
Router Alert for IGMP/RSVP, Record Route for diagnostics, CIPSO for MAC
labelling. A `wake` flag toggles enforcement without detaching the
program.

**Forensics.** Every dropped packet is written to a pcap, byte-exact,
headers and payload intact, with checksums that validate and options that
Wireshark dissects cleanly. The pcap is produced from the same perf event
as the journald line, so correlating "what happened" with "what exactly
was sent" is a `journalctl | grep` plus a `tshark -r` away.

A CVE mitigation deployed blind is half a mitigation. This one takes
action and produces evidence from the same wire event.

---

## Table of contents

1. [Layout](#layout)
2. [Requirements](#requirements)
3. [Quick start](#quick-start)
4. [Building](#building)
5. [The kernel-specific object](#the-kernel-specific-object)
6. [Installing](#installing)
7. [Operating the guard](#operating-the-guard)
8. [The daemon](#the-daemon)
9. [Forensic capture](#forensic-capture)
10. [The ctl](#the-ctl)
11. [Systemd and udev](#systemd-and-udev)
12. [Static binaries for embedded](#static-binaries-for-embedded)
13. [Cross-building with zig](#cross-building-with-zig)
14. [Packaging](#packaging)
15. [Testing](#testing)
16. [Performance](#performance)
17. [Troubleshooting](#troubleshooting)
18. [Kernel compatibility](#kernel-compatibility)
19. [Security model](#security-model)

---

## Layout

src/ C sources
cve_2026_98432_guard.c eBPF XDP program
mtcp-guardd.c userspace event daemon
mtcp-guard-ctl.c config utility
pcap_writer.c/.h libpcap wrapper
xdp_option_probe.c packet generator for testing

services/ systemd unit templates (reference copies)
mtcp-guard-load.service
mtcp-guardd.service
whitelist.conf

tests/ test scripts
test full functional matrix
test-performance iperf3 comparison

build build orchestration (glibc + kernel-specific .o)
build-portable glibc-static binaries
build-zig-alpine musl-static binaries via Alpine chroot
build-matrix multi-kernel object builder (optional)
package.sh produce source + deb + tarball artifacts
install deploy binaries, load, pin, attach
remove detach, unpin, clean up
install-service write systemd units + udev rule, enable both
check-bpf-support kernel capability probe

out/ build artifacts (gitignored)
cve_2026_98432_guard-k5.15.o kernel-specific object
static/ glibc-static binaries
zig/ musl-static binaries per arch
musl-sysroot-/ per-arch sysroots for zig
alpine-chroot-/ Alpine chroots (safe to delete)
dist/ packaged artifacts


---

## Requirements

**Runtime** (on the host where the guard runs):
- Linux kernel 4.18 or newer with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
  `CONFIG_NET`, `CONFIG_INET`
- bpffs mounted at `/sys/fs/bpf` (the install script mounts it if needed)
- `bpftool` and `ip` from `iproute2`
- systemd-journald (for the daemon's log output)

**Build** (on the host where you compile):
- clang with BPF target (`clang -target bpf`)
- gcc
- libbpf-dev, libelf-dev, zlib1g-dev
- Optional: libpcap-dev (for `-p` pcap capture in the daemon)
- Optional: libsystemd-dev (for direct journald logging; syslog fallback
  otherwise)
- Optional: zig 0.13+ (for musl-static embedded binaries)
- Optional: qemu-user-static (for cross-arch sysroot builds on a host
  of a different architecture)

Debian/Ubuntu:

```bash
sudo apt install clang gcc libbpf-dev libelf-dev zlib1g-dev \
                 libpcap-dev libsystemd-dev bpftool iproute2

RHEL/Fedora:                

sudo dnf install clang gcc libbpf-devel elfutils-libelf-devel zlib-devel \
                 libpcap-devel systemd-devel bpftool [iproute](iproute)
                 
Quick start:

# 1. Build everything
./build

# 2. Deploy, load, pin, attach
sudo ./install

# 3. Start the daemon (foreground, with pcap capture)
sudo ./mtcp-guardd -d -p /var/capture/drops.pcap

# 4. Confirm the guard is live
sudo ./mtcp-guard-ctl stats
sudo ./mtcp-guard-ctl drop-ips

# 5. Watch journald for drop events
journalctl -t mtcp-guardd -f

To install as a system service: 

./build
sudo ./install
sudo ./install-service

The install-service script writes the units and the udev rule on the
fly, enables both units, and starts them. From then on the guard loads
at boot and re-attaches to new interfaces as they appear.

Building:

./build detects the running kernel and produces:

    cve_2026_98432_guard-k<major>.<minor>.o — the eBPF object for this
    kernel

    mtcp-guardd — the userspace daemon

    mtcp-guard-ctl — the config utility

    xdp_option_probe — the packet generator for testing
    
Options: 

./build                              # auto-detect running kernel
./build --kernel 5.10                # cross-target 5.10
./build --kernel 4.19 --legacy-maps  # force legacy map ABI
./build --no-userspace               # eBPF object + probe only
./build --no-pcap                    # daemon without pcap support

./build --help shows all options.

The kernel-specific object:

The eBPF object bakes in two things that change across kernel versions:

    Map ABI: struct bpf_map_def for kernels < 5.3, BTF-style maps for
    5.3+

    bpf_perf_event_output helper ID: 26 for kernels < 5.0, 25 for 5.0+

One .o cannot serve two different kernel ABI classes. The build script
therefore names the object after the target kernel:

cve_2026_98432_guard-k4.18.o    (legacy maps, helper 26)
cve_2026_98432_guard-k5.10.o    (BTF maps, helper 25)
cve_2026_98432_guard-k6.6.o     (BTF maps, helper 25)

Multi-boot and mixed-kernel fleets keep one object per kernel version in
the same tree. install and install-service resolve the running kernel
with uname -r and pick the matching object.

If no object matches the running kernel, the install scripts warn and
fall back to the first available one. The kernel's own verifier will
reject the object if the ABI is wrong, so the failure is visible, not
silent.

For cross-building for a different kernel:

./build --kernel 4.19 --legacy-maps
./build --kernel 6.6

The resulting object stays in the tree next to the others.

Installing:

sudo ./install

The install script:

    Deploys the object, install, remove, install-service,
    mtcp-guardd, mtcp-guard-ctl and whitelist.conf into
    /etc/cve-2026-98432-guard/.

    Mounts bpffs if not mounted.

    Loads the object, pins the program, pins the seven maps with shape
    verification, and attaches to every interface (including lo and
    veth*). Native XDP first, generic fallback.

    Prints a summary with program ID, pin paths, per-interface results.

To deploy a specific object (e.g. built for a target kernel):

sudo ./install /path/to/cve_2026_98432_guard-k5.10.o

Operating the guard:

Statistics — per-CPU aggregated, three keys:

sudo ./mtcp-guard-ctl stats

--- XDP statistics (aggregated across 4 CPUs) ---
  key 0 (TCP/IP-options drops): 4
    cpu 0: 1
    cpu 2: 2
    cpu 3: 1
  key 1 (Malformed IPv4 pass): 0
  key 2 (Wake-mode bypasses): 2
    cpu 1: 2
    
Per source counter drop: 

sudo ./mtcp-guard-ctl drop-ips

Whitelist:

sudo ./mtcp-guard-ctl whitelist add 203.0.113.5        # exact IP
sudo ./mtcp-guard-ctl whitelist add 198.51.100.0/24    # /24 prefix
sudo ./mtcp-guard-ctl whitelist list
sudo ./mtcp-guard-ctl whitelist remove 203.0.113.5
sudo ./mtcp-guard-ctl whitelist load /path/to/file
sudo ./mtcp-guard-ctl whitelist save /etc/cve-2026-98432-guard/whitelist.conf

Wake mode — bypass the drop without detaching:

sudo ./mtcp-guard-ctl wake on
sudo ./mtcp-guard-ctl wake off

The daemon:

mtcp-guardd consumes [struct meta_event][packet bytes] from the perf
event map, logs each drop to journald with the interface name, source IP,
and per-source running total, and writes the packet bytes to a pcap if
-p is given.

sudo ./mtcp-guardd                  # foreground
sudo ./mtcp-guardd -d               # daemonize
sudo ./mtcp-guardd -d -p <path>     # daemonize + capture

Signals:

    SIGHUP — reload config and whitelist from
    /etc/cve-2026-98432-guard/whitelist.conf.

    SIGTERM / SIGINT — clean shutdown.

Startup sequence in journald:

mtcp-guardd starting (pid=..., daemonized=1)
pcap: writing drops to /path/to/pcap
config reload: wake=0
whitelist: reload from ...: N added, 0 error(s)
mtcp-guardd ready

Per event logging:

drop iface=veth0 src_ip=192.0.2.99 source_total=1 caplen=60

Every drop produces a line. There is no rate limiting in the daemon. If
journald's own rate limit causes suppression under a flood, tune
RateLimitIntervalSec / RateLimitBurst in the unit or in
/etc/systemd/journald.conf.

Forensic capture:

sudo ./mtcp-guardd -d -p /tmp/drops.pcap

Open the pcap in Wireshark, tshark, tcpdump, Snort, Suricata, Zeek, or
anything else that reads pcap:

tshark -r /tmp/drops.pcap
wireshark /tmp/drops.pcap
tcpdump -r /tmp/drops.pcap -nn -vvv -XX

The capture is byte-exact: checksums validate, IPv4 options are dissected
correctly, TCP flags are set as on the wire. Wireshark's protocol tree
shows the Record Route option, Router Alert, or whatever option was
present — the exact shape that triggered the drop.

The pcap record count matches the journal drop count. If they diverge,
either the perf buffer overflowed (perf buffer lost N event(s) in
journald) or the pcap file couldn't be written (disk full). Both are
visible.

The ctl:

Usage: mtcp-guard-ctl <command> [args]

Commands:
  whitelist add <ip>[/24]      add exact IP or /24 prefix
  whitelist remove <ip>[/24]   remove exact IP or /24 prefix
  whitelist list               list all whitelist entries
  whitelist load <file>        bulk load from file
  whitelist save <file>        dump current whitelist to file
  wake on|off                  set wake flag
  stats                        print aggregated drop statistics
  drop-ips                     print per-source drop counters
  -h, --help                   show this help
  
stats aggregates the per-CPU values and shows the per-CPU breakdown.
drop-ips reads the LRU hash and prints the current top sources.
whitelist list shows entries in their correct sections (exact IPs vs
/24 prefixes).

Systemd and udev:

install-service writes the units and the udev rule inline (no need for
separate .service files in the tree), enables both units, and starts
them.

sys-fs-bpf.mount — ensures bpffs is mounted at boot. Modern systemd
sometimes rejects manually-provided API filesystem mount units. If it
does, the loader's install script mounts bpffs itself, so the guard
still works.

mtcp-guard-load.service — Type=oneshot, RemainAfterExit=yes.
Runs install at boot to load, pin and attach the guard. Depends on the
bpffs mount unit when systemd accepts it.

mtcp-guardd.service — Type=simple. Runs the daemon. Requires the
loader unit, Restart=on-failure, RestartSec=2s, per-unit rate limits
on journald output, RuntimeDirectory=mtcp-guardd for the PID file, and
standard systemd hardening that does not break BPF map access.

90-mtcp-guard-attach.rules — on ACTION=="add", SUBSYSTEM=="net",
restarts mtcp-guard-load.service with --no-block so udev does not
block. When a USB Ethernet, docking station or Wi-Fi adapter appears, the
loader re-runs, attaches to the new interface, and leaves existing
attachments untouched.

systemctl status mtcp-guard-load mtcp-guardd
journalctl -u mtcp-guardd -f
journalctl -u mtcp-guard-load

Static binaries for embedded:

For hosts without glibc, without a package manager, or without a build
chain, the build scripts also produce fully static userspace binaries.
The eBPF object is architecture-independent; the userspace binaries are
not.

glibc-static for the build host or systems with glibc:

./build-portable
# -> out/static/mtcp-guard-ctl
# -> out/static/mtcp-guardd

musl-static for embedded systems:

sudo ./build-zig-alpine --make-sysroot   # one-time, builds per-arch sysroots
./build-zig-alpine                       # builds the binaries
# -> out/zig/x86_64-linux-musl/mtcp-guard-ctl
# -> out/zig/x86_64-linux-musl/mtcp-guardd
# -> out/zig/aarch64-linux-musl/mtcp-guard-ctl
# -> out/zig/aarch64-linux-musl/mtcp-guardd

The musl-static binaries run on any Linux kernel from roughly 3.2 upward,
regardless of glibc version. They have no runtime library dependency.
Copy them to the target, drop them in place, and they work.

The embedded package for any given target consists of:

    One musl-static mtcp-guardd and mtcp-guard-ctl for the target
    architecture

    One cve_2026_98432_guard-k<X.Y>.o per kernel ABI class the fleet uses
    (legacy for 4.18–5.17, BTF for 5.3+)

    The install, remove, install-service scripts

    A whitelist.conf

The eBPF object is the same across architectures. The userspace binaries
are per-architecture.

Cross-building with zig:

build-zig-alpine cross-compiles the userspace binaries against musl,
using Alpine minirootfs + chroot. On a host of a different architecture
(e.g. x86_64 host building for aarch64 Raspberry Pi), qemu-user-static
runs the foreign chroot transparently.

Requirements:

    zig on PATH (ZIG=/path/to/zig ./build-zig-alpine ... if not)

    qemu-user-static for cross-arch (apt install qemu-user-static on
    Debian/Ubuntu, apk add qemu-aarch64 on Alpine)

    binfmt_misc registered for the target arch (usually automatic)

The script builds one sysroot per target architecture under
out/musl-sysroot-<arch>/. Each sysroot contains:

    libbpf.a, built from source in the chroot with
    -mno-outline-atomics (required: Zig's compiler-rt does not provide
    the AArch64 outline atomic helpers, so libbpf must be built with inline
    atomics instead)

    libelf.a, libz.a, libzstd.a, libpcap.a from the Alpine
    packages

    The corresponding headers

The libbpf build happens once per sysroot, in the chroot. Building on
aarch64 via qemu is slow but works. Once the sysroot is ready, the
binaries build in seconds.

Packaging:

package.sh produces:

    cve-2026-98432-guard-<version>-src.tar.gz — source tarball

    cve-2026-98432-guard_<version>_<arch>.deb — glibc-static .deb

    cve-2026-98432-guard-musl_<version>_<arch>.deb — musl-static .deb

    cve-2026-98432-guard-musl-<version>-<arch>.tar.gz — plain tarball
    for embedded targets without dpkg

    SHA256SUMS

Each package contains the binaries, the kernel-specific .o objects, the
scripts, the whitelist, the README and the LICENSE. The postinst does
not auto-install the guard — it tells the operator to run
install-service, so the decision to attach XDP to all interfaces is
explicit.

Testing:

tests/test runs the full functional matrix against the running kernel
and prints every command's output. It exercises:

    build, remove, install

    daemon startup and journald sequence

    attach to lo

    drop path (probe, counters, journal line, pcap contents)

    wake bypass (key 2 increments, no pcap write)

    whitelist exact bypass

    whitelist /24 bypass

    whitelist list / load / save round-trip

    load with malformed file

    drop-ips per-source counters

    stats per-CPU aggregation

    SIGHUP reload

    pcap byte-exactness, checksum validation, option dissection

Run it as root:

sudo ./tests/test

Every check prints [OK] or [FAIL], and a summary at the end counts
passes and failures. If anything fails, the exact command output is
visible in the transcript.

tests/test-performance compares iperf3 throughput with and without the
guard, on a local loopback (worst case) or against a remote server (real
world).

sudo ./tests/test-performance -i veth0
sudo ./tests/test-performance -i enp2s0 --server <lan-host>

Performance

The guard's cost depends heavily on the attach mode and the interface:
Path	Expected cost	Notes
Loopback, xdpgeneric	~40–50%	CPU-bound worst case, synthetic
veth, xdpgeneric	~10–15%	SKB path already exists, one more pass
veth, xdpdrv	~15–20%	veth native path has higher setup cost than a real NIC
Ethernet NIC, xdpdrv	~1–5%	The number that matters for production
Wi-Fi, xdpgeneric	0% (link-bound)	Internet link is the bottleneck

The xdpgeneric mode incurs an SKB allocation per packet that the guard
did not cause. On a real NIC in xdpdrv mode, the guard runs before the
SKB allocation and the cost drops to the XDP fast-path parse: Ethernet
header, up to two VLAN tags, IPv4 header, protocol check, and (for TCP
with options) a whitelist lookup. That is a handful of instructions.

Published benchmarks consistently show native XDP at 5–10× the packet
rate of generic mode, with correspondingly lower CPU per Gbps. The
loopback numbers are the honest worst case; the Ethernet xdpdrv numbers
are what operators should expect.

The pcap write adds one fflush per dropped packet on the daemon side.
This is the right trade for forensic capture: the file is readable by
tshark -r while the daemon is running. It is not on the fast path —
only dropped packets incur it.

Troubleshooting:

The guard doesn't drop packets.

sudo bpftool net show

The interface where traffic should be inspected must list the program.
If it does and traffic still isn't dropped, confirm the packet matches
the drop criteria: IPv4, TCP, IHL > 5, not whitelisted, wake off.

mtcp-guard-ctl stats says "No such file or directory".

The pinned maps aren't at /sys/fs/bpf/cve_2026_98432_*.

sudo bpftool map show | grep 98432
sudo ls -la /sys/fs/bpf/

If the maps exist in the kernel but aren't pinned, the loader failed
partway. Re-run sudo ./install. If they don't exist at all, the program
isn't loaded.

Install fails with "map shape mismatch".

The shape verification in install refused to pin a map whose
(type, key_size, value_size, max_entries) tuple didn't match the
expected shape. This usually means the object was built for a different
kernel than the one running. Check uname -r against the .o name, or
run ./build for the running kernel.

The daemon logs "cannot open events map".

The daemon started before the loader finished pinning. With systemd,
mtcp-guardd.service depends on the loader, so this shouldn't happen. If
running manually, run ./install first.

The daemon logs "perf buffer lost N events".

The perf ring buffer overflowed because the daemon couldn't keep up with
the drop rate. Increase PERF_BUFFER_PAGES_PER_CPU in mtcp-guardd.c
and rebuild. The default is 64 pages per CPU (256 KB per CPU with 4 KB
pages).

Wireshark can't open the pcap.:

Check that the file exists and has non-zero size:

ls -la /tmp/drops.pcap
tshark -r /tmp/drops.pcap

If the daemon was started without -p, no pcap is written. If the file
is zero bytes, either no drops occurred or the daemon was started after
the drops and the perf buffer was already consumed by a previous daemon.

Zig build fails with "unable to find static system library".:

The sysroot doesn't contain the required .a file. Re-run
sudo ./build-zig-alpine --make-sysroot. Check that the sysroot has
libbpf.a, libelf.a, libz.a, libzstd.a:

ls out/musl-sysroot-x86_64/usr/lib/*.a

Zig build fails with __aarch64_ldadd4_sync.

The sysroot's libbpf.a was compiled with -moutline-atomics. Re-run
--make-sysroot with the current script (which builds libbpf from source
with -mno-outline-atomics). Verify:

llvm-nm out/musl-sysroot-aarch64/usr/lib/libbpf.a | grep -c __aarch64_ldadd4_sync

Should be 0.

Chroot is left behind after a failed build, rm -rf fails.

A virtual filesystem is still mounted inside out/alpine-chroot-*.
Unmount it:

sudo umount out/alpine-chroot-*/dev 2>/dev/null || true
sudo umount out/alpine-chroot-*/proc 2>/dev/null || true
sudo rm -rf out


The current script has a trap that should prevent this. If it happens,
the trap didn't fire (e.g. kill -9 or a kernel-level crash).
Kernel compatibility
Kernel	BPF maps	helper ID	Status
4.18 – 4.19	legacy	26	supported
5.0 – 5.2	legacy	25	supported
5.3 – 5.17	BTF	25	fully validated on 5.15
5.18 – 6.x	BTF	25	supported

Minimum kernel: 4.18. Below that, XDP and the required map types are
not available, and no userspace build can change that.

The CVE itself was introduced in kernel 4.4. Kernels 4.4 – 4.17 are
vulnerable but cannot run the guard, because XDP support is either absent
or insufficient. This is a hardware/kernel constraint, not a build
constraint.
Security model

What it protects against. Packets that match the drop criteria (IPv4,
TCP, IHL > 5, non-whitelisted, wake off) are dropped at the XDP hook,
before the kernel parses them. The vulnerable code never runs.

What it does not protect against.

    Non-TCP packets with IPv4 options

    Fragmented IPv4 packets: the BPF program does not defragment, and only
    inspects packets whose full IPv4 header (including options) is in the
    linear data area

    Whitelisted sources sending the attack packet (that's what whitelisting
    is — an explicit operator decision)

    Wake mode being on

XDP generic mode still prevents the packet from reaching the network
stack, but it allocates an SKB first. It is slower than native XDP and
does not benefit from the driver's zero-copy path. Use xdpdrv when the
driver supports it.

Privileges. Install, ctl and daemon require root. Opening pinned
maps requires CAP_BPF on kernels that enforce it. No component runs
unprivileged.

Not a substitute for the vendor kernel patch. The patch fixes the
code. This mitigation drops a packet shape. Where the patch is available,
the patch is the right answer. This exists for environments where the
patch is not available, or not yet.

License:

GPL-2.0. The eBPF program and userspace tools share the GPL license
because the eBPF program uses GPL-only helpers.


### Waarom deze README

Het is geschreven voor de drie doelgroepen tegelijk:

- **De operator** die wil weten hoe hij het installeert, de guard live ziet, en de counters leest. Die leest de Quick start en de Operating-secties.
- **De embedded engineer** die musl-static binaries nodig heeft voor een ARM-board, geen package manager heeft, en een kernel-specifieke `.o` moet shippen. Die leest de "Static binaries for embedded" en "Cross-building with zig" secties.
- **De incident responder** die een pcap in Wireshark opent en wil weten wat de guard heeft gedropt en waarom. Die leest de "Forensic capture" sectie en de Troubleshooting.

De kernel-specifieke `.o`-aanpak, de musl-static binaries, de udev-regel en de packaging zijn allemaal expliciet gedocumenteerd, zodat iemand die het project voor het eerst ziet begrijpt waarom er meerdere `.o`-bestanden zijn en waarom de binaries per architectuur verschillen.

TODO/FIXME: 
- REWORK THIS README
- ADD SECTION ABOUT WHITELISTING
- ADD SECTION ABOUT ENFORCE/MONITOR MODE
- ADD SECTION ABOUT BINDING TO AN IDS SYSTEM (snort etc)
- ADD SECTION ABOUT EMBEDDING SYSTEMS
- ADD SECTION ABOUT TESTING (packetgen)
- ADD SECTION ABOUT KERNEL 4.4 - 4.18 (buy a packeteer if one likes that era)
- ADD SECTION ABOUT BUY ME A COFFEE
- ADD SECTION ABOUT AUDITING

- ADD SCREENSHOTS

- ADD SUDO GUARDS TO ALL SHELL/TEST/INSTALL SCRIPTS
- BUILD NAAR ./bin of ./build ipv in de root of in /out
- PACKAGES INTO ./package
- DIR ./services verwijderen check 
- DIR pre flight check is ook naar tests verzet
- CHECK INSTALL-SERVICE
- DIAGRAMMETJE MAKEN VAN DE WERKING
