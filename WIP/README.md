# cve-2026-98432 — temporary xdp mitigation

**status:** temporary mitigation — not a permanent fix  
**platform tested:** linux / ubuntu 20.04 (should work upwards)
**kernel tested:** `5.15.0-124-generic` (expected to work on newer linux kernels providing the required ebpf and generic xdp functionality. compatibility must be verified on the target kernel.)
**implementation:** ebpf xdp, generic (skb) mode  
**date:** 2026-11-03

---
## 0. prerequisites

### kernel

- linux kernel **4.18 or later** (generic xdp / skb mode support required)
- ebpf syscall enabled (`config_bpf`, `config_bpf_syscall`)
- networking stack enabled (`config_net`, `config_inet`)

kernel config can be verified with:

```bash
grep -e 'config_bpf|config_bpf_syscall|config_net|config_inet' /boot/config-$(uname -r)
```

### build toolchain

- `clang` with bpf target support (`-target bpf`)
- `gcc` (for userspace tools)
- `bpftool` (for map pinning and inspection)
- `pkg-config` and `libbpf` development headers (for `mtcp-guardd` and `mtcp-guard-ctl`)

install libbpf development headers:

```bash
# debian / ubuntu
sudo apt install libbpf-dev

# rhel / fedora
sudo dnf install libbpf-devel
```

### runtime

- root privileges (to load xdp programs and pin bpf maps)
- bpf filesystem mounted at `/sys/fs/bpf`
- `systemd` (for the `mtcp-guard` and `mtcp-guardd` services)

### libbpf optional

userspace tools (`mtcp-guardd`, `mtcp-guard-ctl`) are only built when `libbpf` is
found via `pkg-config`. if `libbpf` is absent, the build succeeds but only the
ebpf object (`cve_2026_98432_guard.o`) and packet probe (`xdp_option_probe`)
are produced. the daemon and config utility will not be available until
`libbpf-dev` / `libbpf-devel` is installed and the build is re-run.

---

## 1. purpose

this project provides a *temporary* network-level mitigation for the ipv4/tcp attack surface associated with **cve-2026-98432**.

the objective is to reduce exposure while a corrected kernel is being prepared, installed and deployed.

the mitigation rejects inbound ipv4 tcp packets containing ipv4 header options. it does this at the xdp ingress hook, before the packet reaches the normal ipv4 and tcp networking stack.

this is deliberately a narrow, fail-open mitigation:

- matching ipv4/tcp packets with ipv4 options are dropped.
- other traffic is passed normally.
- truncated or incomplete ipv4 headers are passed rather than indiscriminately discarded.
- no tcp connection state is maintained.
- no payload inspection or application-layer processing takes place.

**this is not a kernel fix. it is a temporary measure intended to buy time until a corrected kernel has been compiled, installed and boot-tested.**

## 2. why this mitigation exists

the vulnerable attack surface is associated with handling ipv4 tcp traffic and ipv4 header options.

ipv4 header options are an uncommon feature in ordinary modern network traffic. they include mechanisms such as:

- record route (rr)
- internet timestamp
- loose source route
- strict source route
- router alert
- other ipv4 option types

the ipv4 header contains a header-length field, ihl, expressed in 32-bit words.

a normal ipv4 header without options has:

`ihl = 5` (20 bytes)

an ipv4 header containing options has:

`ihl > 5` (more than 20 bytes)

the xdp program uses this distinction to reject ipv4 tcp packets with an extended ipv4 header.

this avoids passing that particular packet class into the kernel's normal tcp processing path.

## 3. how the xdp filter works

the program is attached to network interfaces using xdp generic mode.

its processing sequence is:

1. read the ethernet header.
2. recognise up to two vlan headers.
3. identify ipv4 traffic.
4. check that the fixed ipv4 header is present.
5. check the ipv4 version and ihl.
6. check that the complete ipv4 header, including any declared options, is present.
7. if the protocol is tcp and `ihl > 5`, drop the packet.
8. otherwise, pass the packet to the normal networking stack.

simplified decision logic:

```c
if (ether_type == ipv4) {
    if (ipv4_header_is_incomplete)
        pass;

    if (ipv4_version != 4)
        pass;

    if (ipv4_header_length_is_invalid)
        pass;

    if (ipv4_protocol == tcp && ipv4_ihl > 5)
        drop;
}

pass;
```

the actual implementation also handles up to two vlan tags.

### xdp actions

| condition | action |
|---|---|
| ipv4 tcp, ihl greater than 5 | drop |
| ipv4 tcp, ihl equal to 5 | pass |
| ipv4 udp | pass |
| other ipv4 protocols | pass |
| ipv6 | pass |
| non-ip ethernet traffic | pass |
| incomplete/truncated ipv4 header | pass |

the implementation does not parse tcp options. tcp timestamps, sack and window scaling are not ipv4 header options and remain unaffected.

## 3b. why xdp instead of netfilter or iptables?

this mitigation uses **xdp (express data path)** rather than netfilter/iptables because the objective is to discard matching packets as early as reasonably possible in the linux networking receive path.

### packet processing position

with generic xdp (skb mode), the filter runs at the ingress stage before the packet enters the normal network protocol stack and before netfilter's usual ipv4 processing hooks.

this has several advantages for this particular mitigation:

- **early rejection:** ipv4 tcp packets containing ipv4 header options are discarded before normal ipv4 and tcp processing.
- **reduced processing overhead:** dropped packets do not continue through subsequent networking layers, including the normal netfilter processing path.
- **narrow execution scope:** the program only inspects ethernet, optional vlan headers and the relevant ipv4 header fields. it does not require connection tracking, nat or firewall rule evaluation.
- **predictable filtering logic:** the decision is based on the ipv4 protocol field and ihl value, making the filter small and straightforward to audit.
- **independent deployment:** the mitigation is implemented as an ebpf program and does not require modifying existing iptables or nftables firewall rules.

### why not iptables or netfilter?

iptables and nftables are perfectly valid ways to implement this same filtering rule. in fact, netfilter-based filtering is a legitimate alternative and may be preferable where an administrator already manages ingress filtering centrally through the firewall.

however, those mechanisms operate later in the receive path than xdp generic mode.

for this specific use case, filtering before normal ipv4/tcp processing is desirable because the vulnerability concerns the handling of ipv4 tcp packets carrying ipv4 header options.

### generic xdp (skb mode)

this project deliberately uses generic xdp rather than driver-specific native xdp.

generic xdp operates on the skb-based receive path and therefore provides broader compatibility with network drivers that do not implement native xdp support.

the trade-off is that generic xdp does not provide the same early execution point or performance characteristics as native driver-mode xdp. it should not be confused with hardware-offloaded xdp.

### design decision

the choice of xdp is not based on the assumption that netfilter is insecure or unsuitable.

it is based on placing this particular packet filter as early as practical in the linux receive path, while retaining broad compatibility through generic xdp.

**the objective is to reject the relevant packet class before it reaches the vulnerable ipv4/tcp processing path, not to replace the host firewall.**

## 4. what this mitigation blocks

the filter blocks **all ipv4 tcp packets carrying ipv4 header options**, not just record route.

this includes packets containing, for example:

- record route
- ipv4 timestamp
- loose source route
- strict source route
- router alert, when carried in an ipv4 tcp packet
- other ipv4 options

the filter does not distinguish between individual ipv4 option types. it rejects the entire ipv4 tcp packet whenever the ipv4 header length exceeds 20 bytes.

this is intentional: a broad and simple rule is preferable to an incomplete option-type blacklist for this temporary mitigation.

## 5. what it does not block

this mitigation has deliberately limited scope.

it does not:

- fix the vulnerable kernel code.
- protect interfaces on which the xdp program is not attached.
- filter ipv4 tcp packets arriving through paths that bypass the attached ingress hooks.
- filter loopback traffic.
- filter ipv6 traffic.
- filter ipv4 udp or other non-tcp protocols.
- reject normal ipv4 tcp packets with a 20-byte ipv4 header.
- inspect tcp options.
- inspect tcp payloads.
- detect or prevent unrelated kernel vulnerabilities.
- replace a kernel security update.

it also does not perform general ip packet validation. incomplete or malformed packets outside the specific checks implemented by the program may still be passed to the kernel.

**do not interpret a successful xdp deployment as proof that the host is no longer vulnerable.**

## 6. statistics and auxiliary maps

the program uses several pinned bpf maps in `/sys/fs/bpf/`:

### `cve_2026_98432_stats` — per-cpu statistics

map properties:

- type: `percpu_array`
- key size: 4 bytes
- value size: 8 bytes
- maximum entries: 2

counters:

| key | meaning |
|---|---|
| 0 | ipv4 tcp packets with ipv4 options dropped |
| 1 | incomplete/truncated ipv4 headers passed |

because this is a per-cpu map, values are maintained separately for each cpu.
a zero counter does not necessarily indicate a problem. it may simply mean
that no matching traffic has been observed.

### `cve_2026_98432_whitelist` — whitelist exact-match map

map properties:

- type: `hash`
- key size: 4 bytes (`__u32` source ip)
- value size: 1 byte (`__u8`)
- maximum entries: 512

exact-match whitelist of source ipv4 addresses. entries here bypass the drop
action entirely. lookup order: bitmap fast path first, then this hash map.

### `cve_2026_98432_whitelist_bm` — whitelist /24 bitmap fast path

map properties:

- type: `array`
- key size: 4 bytes (`__u32` /24 prefix index = src_ip >> 8)
- value size: 4 bytes (`__u32` bitmask)
- maximum entries: 256

bitmap fast path for /24 whitelist granularity. each entry represents one /24
prefix. bit n in the bitmask covers source ips where `((src_ip >> 3) & 0x1f) == n`.
consulted before the exact-match hash map.

### `cve_2026_98432_drop_ips` — drop source ip tracker

map properties:

- type: `lru_hash`
- key size: 4 bytes (`__u32` source ip)
- value size: 8 bytes (`__u64` drop count)
- maximum entries: 4096

lru hash tracking how many times each source ip has been dropped. incremented
on every drop of a non-whitelisted packet with ipv4 options.

### `cve_2026_98432_events` — userspace notification map

map properties:

- type: `perf_event_array`
- key size: 4 bytes
- value size: 4 bytes
- maximum entries: 1024

perf event buffer used to notify `mtcp-guardd` of each drop event. the daemon
reads this map via `perf_buffer__poll()` (epoll-backed, event-driven).

### `cve_2026_98432_config` — runtime configuration

map properties:

- type: `array`
- key size: 4 bytes
- value size: 4 bytes (`__u32` flags)
- maximum entries: 1

single-entry configuration map. key 0 holds a flags word; bit 0 is the "wake"
flag controlling whether drops are reported to the daemon.


## 7a build

the project includes a build script that checks if the current running kernel has bpf support.

### requirements

- linux kernel with ebpf syscall support.
- generic xdp (skb mode) support.
- clang/llvm with bpf target support.
- `bpftool` (for capability inspection).
- bash and standard build utilities.

### build procedure

run from the project directory:

```bash
./build
```

### build output

the expected output is:

```text
cve_2026_98432_guard.o
xdp_option_probe
mtcp-guardd        (when libbpf is available)
mtcp-guard-ctl     (when libbpf is available)
```

`cve_2026_98432_guard.o` is the ebpf object loaded by the installer.

`mtcp-guardd` is the userspace notification daemon. it reads the perf event
buffer from `cve_2026_98432_events`, logs drop events via syslog, and supports
sighup configuration reload.

`mtcp-guard-ctl` is the configuration utility for managing the whitelist,
wake flag, statistics, and drop-ip tracking at runtime.

### architecture portability

the c source is architecture-independent, but the generated object must be compiled using a toolchain capable of producing ebpf bytecode.

the resulting ebpf object is not a native executable for the host cpu. the linux kernel loads and verifies the ebpf instructions independently of whether the host cpu is x86-64 or arm64.

### important

a successful build does not guarantee that the kernel will accept the program.

the kernel's ebpf verifier performs the definitive safety and compatibility checks when the object is loaded.

the deployment should only proceed after successful compilation and verifier acceptance.

## 7b installation

the installer is:

`install`

the deployment directory is:

`/etc/cve-2026-98432-guard/`

the installer deploys:

- `cve_2026_98432_guard.o`
- `install`
- optional documentation and checker files, when present

the pinned bpf objects are:

```text
/sys/fs/bpf/cve_2026_98432_guard
/sys/fs/bpf/cve_2026_98432_stats
/sys/fs/bpf/cve_2026_98432_whitelist
/sys/fs/bpf/cve_2026_98432_whitelist_bm
/sys/fs/bpf/cve_2026_98432_drop_ips
/sys/fs/bpf/cve_2026_98432_events
/sys/fs/bpf/cve_2026_98432_config
```

the installer:

1. checks required tools and permissions.
2. ensures that bpf filesystem support is available.
3. loads the program if it is not already pinned.
4. reuses an existing pinned program rather than silently replacing it.
5. checks the statistics map.
6. scans available non-loopback network interfaces.
7. attaches the program in generic xdp mode where no conflicting xdp program is present.
8. does not overwrite an unrelated xdp attachment.

run as root:

```bash
sudo ./install
```

the installer is designed to be repeatable. running it again should recognise existing attachments rather than attaching duplicate instances.

### important: replacing an existing program

copying a newly compiled object into the deployment directory does not automatically replace an already pinned and attached program.

this is intentional. it prevents an ordinary installer run from silently changing the active network filter.

a deliberate reload or migration procedure is required when replacing the active program.

## 8. verification

the checker is:

`checkinstall`

run:

```bash
./checkinstall
```

it checks:

- the pinned program.
- the program id.
- the pinned statistics map.
- whether the map belongs to the program.
- xdp attachments on available non-loopback interfaces.
- whether the attached program ids match the expected program id.
- the per-cpu statistics.

a healthy installation should report:

```text
correct attachments: 3
missing/wrong: 0
warnings: 0
errors: 0
installation healthy
```

the expected program id is not a permanent constant. it can change after a deliberate reload.

## 9. safe functional test

the filter can be tested without exercising the vulnerability.

the test consists of sending one ordinary tcp syn packet with an ipv4 record route option from a separate, controlled machine to an interface on which the filter is attached.

there is no exploit payload, no malformed tcp structure and no attempt to trigger the vulnerability. the purpose is simply to verify that an ipv4 tcp packet with `ihl > 5` is dropped before reaching the normal networking stack.

requirements:

- use a second machine under your control.
- send to an ip address belonging to the protected host.
- use an unused tcp destination port.
- do not use a third-party destination.
- run the test only on a network where you are authorised to transmit packets.

example using scapy on the test machine:

```python
#!/usr/bin/env python3

from scapy.all import ip, tcp, ipoption_rr, send

target = "192.0.2.10"  # replace with the protected host's ip
source_port = 49152
dest_port = 65000

packet = (
    ip(
        dst=target,
        options=[ipoption_rr()],
    )
    /
    tcp(
        sport=source_port,
        dport=dest_port,
        flags="s",
        seq=1,
    )
)

print(f"sending one benign ipv4/tcp packet to {target}:{dest_port}")
send(packet, count=1, verbose=false)
print("packet sent.")
```

`192.0.2.10` is a documentation-only example address. replace it with the actual address of the controlled test host.

on the protected host, inspect the statistics before and after the test:

```bash
sudo bpftool map dump pinned /sys/fs/bpf/cve_2026_98432_stats
```

expected result:

- counter key `0` increases by one on the cpu that processed the packet.
- the packet does not reach the normal tcp stack.
- no tcp connection is established.

the counter is per-cpu, so inspect all returned cpu values rather than expecting a single global counter.

a negative result is not conclusive until the packet's ingress interface and the xdp attachment on that interface have been confirmed.

### normal traffic regression test

after deployment, verify ordinary connectivity:

- dns resolution
- http and https
- ssh
- existing tcp connections
- wi-fi and wired connectivity, as applicable

normal ipv4 tcp traffic without ipv4 options should continue to work.

## 10. systemd service and reboot persistence

the xdp filter is not inherently reboot-persistent.

although the program and its statistics map are pinned in `/sys/fs/bpf/`, these pinned objects exist only for the lifetime of the running kernel. they do not survive a system reboot.

after reboot:

- the xdp program is no longer loaded.
- the pinned bpf program and map no longer exist.
- all xdp interface attachments are gone.
- the network interfaces must be attached again.

### automatic loading through systemd

two systemd units are provided:

- `mtcp-guard.service` — oneshot service that runs the installer to deploy
  the xdp filter at boot (reboot persistence for the filter).
- `mtcp-guardd.service` — simple service that runs the `mtcp-guardd` userspace
  daemon. it reads the perf event buffer from `cve_2026_98432_events` and logs
  drop events via syslog. supports `sighup` for configuration reload.

install both unit files:

```bash
sudo install-service
```

this installs `mtcp-guard.service` and `mtcp-guardd.service` into
`/etc/systemd/system/`, reloads systemd, and enables both services.

the `install-service` script (installed by the `install` step) places:

- `/etc/systemd/system/mtcp-guard.service`
- `/etc/systemd/system/mtcp-guardd.service`

enable both at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mtcp-guard.service
sudo systemctl enable mtcp-guardd.service
```

start both immediately:

```bash
sudo systemctl start mtcp-guard.service
sudo systemctl start mtcp-guardd.service
```

the `mtcp-guardd.service` unit is configured with `after=mtcp-guard.service`
so the xdp filter is loaded before the daemon starts reading events.

install the unit files:

```bash
sudo install-service
```

enable both at boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable mtcp-guard.service
sudo systemctl enable mtcp-guardd.service
```

start both immediately:

```bash
sudo systemctl start mtcp-guard.service
sudo systemctl start mtcp-guardd.service
```

### mtcp-guardd — userspace notification daemon

`mtcp-guardd` reads drop events from the `cve_2026_98432_events` perf event
buffer using `perf_buffer__poll()` (epoll-backed, event-driven — no busy
polling). each drop event is logged via syslog:

```
drop src_ip=192.0.2.10 count=1
```

the daemon supports:

| flag/event | behavior |
|---|---|
| `-d` | daemonize (fork into background) |
| `sighup` | reload configuration from the `cve_2026_98432_config` map |
| `sigterm` / `sigint` | clean shutdown |
| pid file | `/run/mtcp-guardd.pid` |

the wake flag (bit 0 of key 0 in `cve_2026_98432_config`) controls whether
drop events are reported to the daemon.

### mtcp-guard-ctl — runtime configuration utility

`mtcp-guard-ctl` manages whitelist entries, the wake flag, and statistics at
runtime. it opens pinned maps via `bpf_obj_get`.

usage:

```bash
# whitelist management
./mtcp-guard-ctl whitelist add 192.0.2.10          # exact ip allow
./mtcp-guard-ctl whitelist add 192.0.2.0 /24        # /24 prefix allow
./mtcp-guard-ctl whitelist remove 192.0.2.10        # remove allow
./mtcp-guard-ctl whitelist list                      # list all entries
./mtcp-guard-ctl whitelist load /etc/cve-2026_98432_guard/whitelist.conf   # bulk-load from file
./mtcp-guard-ctl whitelist save /etc/cve-2026_98432_guard/whitelist.conf   # dump maps to file

# wake flag
./mtcp-guard-ctl wake on                             # enable daemon reporting
./mtcp-guard-ctl wake off                            # disable daemon reporting

# statistics
./mtcp-guard-ctl stats                               # show drop statistics
./mtcp-guard-ctl drop-ips                            # show per-source drop counts
```

### persistent whitelist (repopulation on reboot/reload)

a whitelist configuration file is installed at:

```
/etc/cve-2026_98432_guard/whitelist.conf
```

format: one entry per line, either a bare ip or a `/24` prefix. lines starting
with `#` are comments; blank lines are ignored.

```
# /etc/cve-2026_98432_guard/whitelist.conf
192.0.2.10
192.0.2.0/24
10.0.0.5
```

the `mtcp-guardd.service` unit runs `execstartpre` to bulk-load this file into
the bpf maps before the daemon starts:

```
execstartpre=/etc/cve-2026_98432-guard/mtcp-guard-ctl whitelist load /etc/cve-2026_98432_guard/whitelist.conf || true
```

this ensures whitelisted ips are repopulated after every reboot (the bpf maps
do not survive a kernel restart).

sending `sighup` to the daemon (`systemctl reload mtcp-guardd.service`) also
reloads `whitelist.conf`, so runtime whitelist changes can be applied by:

1. editing `/etc/cve-2026_98432_guard/whitelist.conf`
2. running `sudo systemctl reload mtcp-guardd.service`

alternatively, use `mtcp-guard-ctl whitelist add` / `remove` for live changes,
then `mtcp-guard-ctl whitelist save` to persist them back to the file.

### whitelisting examples — common scenarios

all `mtcp-guard-ctl` commands require root (they write to pinned bpf maps under
`/sys/fs/bpf/`).

#### allow a single ip address

```bash
# allow 192.0.2.10 (exact match via hash map)
sudo ./mtcp-guard-ctl whitelist add 192.0.2.10

# verify
sudo ./mtcp-guard-ctl whitelist list
```

output:

```text
--- whitelist hash (exact ips) ---
192.0.2.10
--- whitelist bitmap (/24 prefixes) ---
(none)
```

#### allow an entire /24 subnet

```bash
# allow all hosts in 192.0.2.0/24 via the bitmap (fast path)
sudo ./mtcp-guard-ctl whitelist add 192.0.2.0 /24
```

the bitmap uses `idx = src_ip >> 8` and `bit = 1 << ((src_ip >> 3) & 0x1f)`,
so each /24 consumes one bit in a 256-entry array.

#### remove a single ip from the whitelist

```bash
sudo ./mtcp-guard-ctl whitelist remove 192.0.2.10
```

note: `remove` only affects exact-ips in the hash map. to remove a /24 prefix,
clear the corresponding bitmap entry:

```bash
# remove 192.0.2.0/24 from the bitmap
sudo ./mtcp-guard-ctl whitelist add 192.0.2.0 /24   # (re-add to confirm current state)
# then edit the whitelist file and reload, or clear via direct map manipulation.
```

#### bulk-load whitelist from a file

create `/etc/cve-2026_98432_guard/whitelist.conf`:

```text
# my whitelist
192.0.2.10          # specific host
192.0.2.0/24        # internal subnet
10.0.0.5            # management host
172.16.0.0/24       # another subnet
```

load it:

```bash
sudo ./mtcp-guard-ctl whitelist load /etc/cve-2026_98432_guard/whitelist.conf
```

any invalid lines are skipped with a warning; the command reports how many
entries loaded and how many errored.

#### save current whitelist to a file

dump the live bpf maps to a file for backup or audit:

```bash
sudo ./mtcp-guard-ctl whitelist save /etc/cve-2026_98432_guard/whitelist.conf
```

this writes both the hash map entries (exact ips) and bitmap entries (/24
prefixes) in the config file format, so the file can be reloaded later.

#### live edit + persist workflow

```bash
# 1. add a temporary allow
sudo ./mtcp-guard-ctl whitelist add 198.51.100.99

# 2. verify it took effect
sudo ./mtcp-guard-ctl whitelist list

# 3. persist to the config file
sudo ./mtcp-guard-ctl whitelist save /etc/cve-2026_98432_guard/whitelist.conf

# 4. confirm the daemon picks it up on reload
sudo systemctl reload mtcp-guardd.service
```

#### enable / disable daemon reporting (wake flag)

the wake flag (bit 0 of key 0 in `cve_2026_98432_config`) controls whether
drop events are reported to `mtcp-guardd`:

```bash
sudo ./mtcp-guard-ctl wake on    # enable drop event reporting
sudo ./mtcp-guard-ctl wake off   # disable drop event reporting
```

when reporting is disabled, drops still occur (xdp filter still active) but
no perf events are emitted.

#### view drop statistics

```bash
# total drops (per-cpu stats map)
sudo ./mtcp-guard-ctl stats

# per-source drop counts (lru drop_ips map)
sudo ./mtcp-guard-ctl drop-ips
```

#### verify whitelisted traffic is not dropped

1. send a tcp packet with ipv4 options (ihl > 5) from a whitelisted ip.
2. check `journalctl | grep mtcp-guardd` — no drop event should appear.
3. check `./mtcp-guard-ctl stats` — drop counter should not increment.

### service status and diagnostics

check the xdp guard service:

```bash
systemctl status mtcp-guard.service
```

check the daemon service:

```bash
systemctl status mtcp-guardd.service
```

inspect startup logs:

```bash
journalctl -u mtcp-guard.service -b
journalctl -u mtcp-guardd.service -b
```

daemon drop events are logged to syslog and visible via:

```bash
journalctl | grep mtcp-guardd
```

### important limitations

the service only attaches the filter to network interfaces that exist when the installer runs.

interfaces created or connected later may not automatically receive the xdp attachment. this includes usb network adapters and some dynamically created virtual interfaces.

additional udev or network-manager integration may be required for systems where interfaces appear after service startup.

`before=network.target` and `systemd-udev-settle.service` provide startup ordering, but do not guarantee that every possible network interface is available at that point.

### reboot safety

| deployment method | survives reboot? |
|---|---|
| manual bpf load and attachment | no |
| pinned bpf objects only | no |
| installer executed manually | no |
| installer executed by enabled systemd service | automatically reloaded at boot |
| interfaces appearing after service execution | not automatically covered |

**conclusion:** the mitigation is reboot-safe only when the systemd service is installed, enabled and successfully executed at every boot. without that service, the host returns to its unfiltered state after reboot.

## 11. remove / uninstall

the `remove` script removes the runtime bpf filter only — it detaches xdp from all network interfaces, removes the pinned program and all pinned bpf maps, stops `mtcp-guardd.service`, and removes the pid file.

it intentionally does **not** remove:

- systemd unit files (`mtcp-guard.service`, `mtcp-guardd.service`)
- `/etc/cve-2026_98432_guard/` directory (including `whitelist.conf`)

### usage

```bash
sudo ./remove
```

### what is removed

| item | removed? | notes |
|---|---|---|
| xdp attachments on all interfaces | yes | only interfaces with matching program id |
| pinned program `/sys/fs/bpf/cve_2026_98432_guard` | yes | |
| pinned map `stats` | yes | |
| pinned map `whitelist` | yes | |
| pinned map `whitelist_bm` | yes | |
| pinned map `drop_ips` | yes | |
| pinned map `events` | yes | |
| pinned map `config` | yes | |
| `mtcp-guardd.service` (stopped) | yes (stopped only) | service file is kept |
| `/run/mtcp-guardd.pid` | yes | |
| `/etc/systemd/system/mtcp-guard.service` | no | kept |
| `/etc/systemd/system/mtcp-guardd.service` | no | kept |
| `/etc/cve-2026_98432_guard/` | no | kept (incl. whitelist.conf) |

### reboot note

pinned bpf objects exist only for the lifetime of the running kernel. a reboot will clear any remaining bpf state even if `remove` is not run.

## 12. sha-256 integrity checks

the project includes a `sha256sums` manifest containing sha-256 hashes of the project files.


```
39c089b872ca11bdb8d827ac774d9e4c93a022b0d2dc030bcdef55e5c1616ff4  ./build
5fc9542cdaf40d3c689cef5aaa300e4028ca02771cb45d10491f1629167b6c86  ./check-bpf-support
7c5c16439f8a9393fcb865f9b0e9287d3cdbdfa8394cd181dfa3cf55552bfc99  ./checkinstall
6c4352f0b062cc8d936c29d1f2ad65b154c0efccaa36c94b0e94d1af9a17b895  ./cve_2026_98432_guard.c
8d4d07a775a80d738f97778831bc518b9ee7985b4a92af91fc9fe436fed0ccd7  ./cve_2026_98432_guard.o
a515ac841aefb090586436c1dadc1e39badc8b4ef7920e93c9a01041b649c22b  ./install
e6c8450ad6f64f05d11be14a14945c9fc7f9217232ddd43cb7d2b68f136f1f75  ./install-service
d317f9b33084554436c19cce47f54d4cea74a0c4e8be98821927517dbc48bd0d  ./mtcp-guard.service
efc78963c6ba695fe83b350629eee01c811f234756549989f371d8e91601ea79  ./xdp_option_probe
3e87e88322c9dabe38d4ff2d4b82e4180c6474ca0da548543e1aed537d94e0db  ./xdp_option_probe.c
52c3597e1ada678f65d00d2490a177a4a7d034e32c693723508bc869dcc492d7  ./xdp_option_probe_auto
```

**integrity note:** sha-256 checks detect accidental or unauthorised changes only when the expected manifest is trusted. they do not independently authenticate the author or origin of the files. for stronger provenance, retain a trusted copy of the manifest or sign it with gpg.

## 12. license

gpl-3.0-only license

## 13. security disclaimer and limitation of liability

see disclaimer

## 14. support the project ☕

this project is developed and maintained independently.

if this workaround saved you time, helped secure a system, or provided a useful starting point for your own research, consider supporting me.

donations are entirely voluntary and help cover development time, testing hardware, infrastructure and ongoing maintenance.

support can be done by eth, btc or trc20 on 
```
[ eth 0x3c4cc45af4bdd51c050c4e5d194764a9969eaf43 ]
[ btc bc1qm4kle4s2jvujjjfaxg2uatw868uv4ljafnaj80 ]
[ usdt trc20 tfu3ws9y39mhfkmr6sffndpd8yvzihm8nw ] 
```

thank you for supporting independent open-source development!

[![demo install](screenshots/001.jpeg)](screenshots/001.jpeg)
