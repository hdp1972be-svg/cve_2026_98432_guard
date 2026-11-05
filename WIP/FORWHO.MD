## FOR WHO

This guard is for you if **you cannot rebuild, replace, or patch your
kernel right now** — and you still need to stop CVE-2026-98432
exploitation today.

The standard response to a kernel vulnerability is: apply the vendor
patch, reboot, done. If you can do that this week, do that. This guard
is not for you. The vendor patch is the correct fix, and it fixes the
problem at the source. Nothing in this repository is better than a
patched kernel.

This guard is for everyone else.

### You are in scope if any of these is true

**You are running an appliance or an embedded system.**
Your kernel is vendor-supplied, vendor-signed, and cannot be
independently rebuilt or replaced outside the vendor's release cycle.
The next firmware release is weeks or months away. You do not have the
kernel source, the toolchain, or the signing key. You cannot rebuild
your kernel because there is nothing to rebuild.

**You are running an industrial or OT system.**
The machine controls production equipment, a piece of machinery, a
process line. Rebooting it means stopping production. Applying a
kernel update means requalifying the entire control stack. Your
change-control process for a kernel update is measured in weeks. You
cannot reboot your way out of this, and the CVE does not wait for your
change-control cycle.

**You are in a regulated environment.**
Kernel changes are formal changes. They go through documented
approval, testing, and sign-off. The full cycle for a kernel patch is
long. You have an emergency-change procedure for smaller, more
targeted mitigations. This guard — attach, drop, log, detach — fits
that procedure. A full kernel rebuild does not.

**You are running an end-of-life kernel.**
The kernel still works. The system still does useful work. The vendor
has stopped shipping updates for it. There is no patched kernel to
apply, from anyone. You cannot rebuild what nobody maintains.

**You are responsible for a large heterogeneous fleet.**
Thousands of endpoints, hundreds of kernel versions, dozens of
hardware variants. Coordinating a rebuild-and-reboot across the fleet
takes longer than the attack window. You need something you can
deploy to the fleet *today* while the proper patch cycle proceeds in
the background.

**You are on a lab or air-gapped system.**
No internet, no package mirror, no path to a new kernel package.
You have the object file and you have `bpftool`, or you have neither
but you can copy them in. You cannot fetch a rebuilt kernel because
there is nowhere to fetch it from.

**You have a support contract that doesn't include kernel updates.**
Or your vendor's patching window is quarterly, or your internal policy
requires three approvals for kernel changes, or your organization
decided years ago that "we don't rebuild kernels on this class of
box." The specifics vary; the pattern is the same. The patch exists.
It just isn't reachable for you right now.

### You are out of scope if any of these is true

**You can apply the vendor kernel patch this week.**
Do that. Rebuild, reboot, verify. The vendor patch fixes the
vulnerability at the source; this guard drops a packet shape and calls
it a day. When both are available, the patch is always the right
answer.

**Your kernel is a mainstream distribution kernel with an available
security update.**
Debian, Ubuntu, RHEL, Fedora, SUSE, Arch — if the fix is in the
distribution's security channel and you can install it, install it.
The guard is not a substitute for a security update that is one
`apt` command away.

**You are running a kernel you built yourself.**
You have the source. Rebuild it. That is the correct fix, and you are
the one person for whom it is trivial.

**You have no way to load BPF programs at all.**
The guard requires `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, a mounted
bpffs, and a kernel from 4.18 or newer. If any of those is missing,
this guard cannot run. There is no fallback that doesn't involve the
kernel.

**You do not control the host's interfaces or networking.**
The guard attaches to interfaces at the XDP hook. If you cannot attach
a program to those interfaces — because the network is owned by
another team, because the host is a container without `CAP_NET_ADMIN`,
because the interfaces are managed by an SDN you don't administer —
the guard has nowhere to run. Fix that first.

**You need a general-purpose IDS.**
This guard detects exactly one traffic shape (IPv4/TCP with header
options) associated with one CVE. It is not a general-purpose
intrusion detection system. It will not catch port scans, protocol
anomalies, authentication abuse, data exfiltration, or anything else
outside its narrow scope. If that's what you need, deploy Suricata,
Zeek, or whatever your environment standardizes on. This guard is a
targeted mitigation, not a sensor platform.

**You need formal IDS/IPS certification.**
The guard is an inline eBPF program. It has no certification from
any certification body. If your compliance regime requires a certified
IDS/IPS to sit on the wire, this is not that product and was never
intended to be.

### The honest summary

**If you can patch your kernel, patch your kernel.** This guard
does not change that. The vendor patch is the fix; this guard is what
you do when the fix isn't available to you yet.

**If you cannot patch your kernel** — for reasons of hardware,
software, change control, end-of-life, scale, or air-gap — **this
guard is a mitigation you can deploy in the time you actually have.**
It compiles without kernel headers, loads into the running kernel,
attaches to your interfaces, drops the attack traffic, counts every
drop, and detaches cleanly in seconds. It buys you the window between
"CVE disclosed" and "patch deployed." For some of you, that window is
weeks. For some of you, it's forever. Either way, this guard exists to
fill it.

**If you are unsure which side you're on**, the answer is usually:
look at your change-control process for a kernel update. If you can
get a kernel patch deployed in the next 7 days, you are the "patch
your kernel" case. If the answer is "weeks" or "unknown" or "we
don't have a process for that," you are the case this guard exists
for.
