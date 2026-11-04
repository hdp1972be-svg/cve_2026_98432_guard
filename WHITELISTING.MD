### Why whitelisting exists

The drop policy is deliberately narrow: it targets **IPv4/TCP packets
that carry IPv4 options** (`IHL > 5`). That shape is strongly associated
with CVE-2026-98432 exploitation, but it is **not** exclusively used by
attackers. IPv4 header options are part of the protocol, they were
designed for legitimate purposes, and some real systems still emit them.

The guard cannot distinguish a malicious IPv4 option from a benign one
without parsing every option's semantics in the BPF program — which
would be expensive, brittle, and outside the scope of a temporary
mitigation. So it makes the only safe choice available at this layer:
**drop by default, and let the operator carve out known-good sources.**

That's what the whitelist is for. It is not a "trusted network" list in
the firewall sense; it is a **correctness escape hatch** — a way to tell
the guard "I know this source sends the packet shape you're looking for,
and I want it to reach the stack anyway."

#### Legitimate uses of IPv4 header options

These are real, standards-defined uses of `IHL > 5` that appear in
production networks:

- **Record Route (RR, option type 7).** Diagnostic tooling sometimes uses
  it to trace the path a packet takes. Rare, but real.
- **Timestamp (TS, option type 68).** Older latency-measurement and
  path-tracing tools use it. Some embedded and industrial systems still
  send it.
- **Loose Source Route (LSRR, type 131) and Strict Source Route (SSRR,
  type 137).** Legacy but occasionally still present in lab and test
  environments, and in some IoT/fleet-management products.
- **Router Alert (option type 148, `0x94`).** Used by protocols that
  need every router along the path to inspect the packet — RSVP (for
  QoS reservation), IGMPv2/v3 (for multicast group management), and MLD
  (IPv6's equivalent, not relevant here but same idea). **This is the
  most common legitimate case.** A host participating in IGMP or RSVP
  will send TCP packets with a Router Alert option under some
  conditions, and the guard will drop them.
- **Security (SEC, type 130) and CIPSO (type 134).** Used in some
  high-security environments for mandatory access control labeling.
  Extremely rare but present in certain government and defense
  networks.
- **Experimental / private-use options (types 30, 94, 158, 222).**
  Vendor-specific uses, in-house monitoring, proprietary protocols.

In a data-center, enterprise, or managed-cloud network, none of these
appear often. In an industrial network, an IoT deployment, a lab, or an
environment that still uses legacy multicast tooling — some of them
appear regularly. **In those environments, a strict drop policy will
break working systems.**

#### What happens if you don't whitelist

If a legitimate host sends TCP packets with IPv4 options and is not
whitelisted, the guard will drop them. The failure mode is usually
silent and specific:

- **IGMP membership reports** with Router Alert get dropped → the host
  fails to join a multicast group → it doesn't receive the stream it
  subscribed to.
- **RSVP reservations** get dropped → QoS setup fails → the host's
  guaranteed-bandwidth flow degrades to best-effort.
- **Record Route / Timestamp tooling** gets dropped → the diagnostic
  produces no output, with no error to the operator.
- **CIPSO-labeled traffic** gets dropped → the MAC policy on the
  receiving host sees no packets and can't determine whether to allow
  or deny access, with confusing results downstream.

In every case, the guard is doing exactly what it was told to do — it's
the operator who needs to tell it that this source is fine. That's what
the whitelist accomplishes.

#### What to whitelist, and what not to

**Do whitelist:**

- Monitoring agents and management planes that send IPv4 options as
  part of their protocol (identify them by observing `drop-ips` when
  the guard is first enabled).
- Multicast routers and IGMP/RSVP participants that legitimately emit
  Router Alert.
- Diagnostic and trace tooling hosts that use Record Route or Timestamp.
- Known-good lab systems and test rigs that generate the packet shape
  for testing purposes (including, of course, `xdp_option_probe`
  itself, if you want a self-test from the same host).
- Any source that shows up in `drop-ips` **and** whose traffic is
  confirmed legitimate by inspection.

**Do not whitelist:**

- Broad ranges or `/24`s covering unknown hosts. A `/24` entry is 254
  possible sources; if even one of them is compromised, the whitelist
  becomes the attack path. Use exact IPs where possible.
- Sources you haven't confirmed. "It showed up in `drop-ips`" is not a
  reason to whitelist — it's a reason to investigate.
- Any address you don't control or trust. A whitelist entry is a
  promise: "anything from here can send the attack packet and reach
  the stack."
- The attacker's IP, obviously. If `drop-ips` shows a source and you
  can't confirm it's benign, that's an incident, not a whitelist entry.

#### The narrowness of the guard is its point

The guard's narrowness is a feature, not a limitation. It targets a
specific packet shape associated with a specific CVE, and it operates
in a way that lets operators say "yes, this exception is expected."
That's what makes it deployable in environments where a broad drop
rule would break too much and a wide-open allow rule would protect
nothing.

The whitelist is how you preserve that narrowness while still allowing
legitimate use of IPv4 options. It's the mechanism that turns "drop
all IPv4/TCP with options" into "drop all IPv4/TCP with options
**except from sources I've vetted**" — which is the only policy that
can be deployed safely on a general-purpose network, and it's why the
whitelist exists as a first-class feature rather than an afterthought.
