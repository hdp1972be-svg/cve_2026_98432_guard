Note on triggering with udev

The loader unit attaches XDP to interfaces that exist when it runs at boot. If an interface is hot-plugged later (USB Ethernet, docking station, Wi-Fi adapter, USB tethering), or if an interface disappears and reappears (driver reload, USB re-enumeration, suspend/resume), the guard will not be attached to it. This is a normal limitation of static attachment, not a bug.

There are three ways to handle this, depending on how much automation you want:

Option A — Manual re-attach. After plugging the interface in:
bash

sudo ip link set dev <iface> xdpgeneric pinned /sys/fs/bpf/cve_2026_98432_guard

Or re-run the loader unit:
bash

sudo systemctl restart mtcp-guard-load.service

install is idempotent: it reuses the already-pinned program, detects the interfaces that already have the guard attached, and attaches to any newly appeared ones.

Option B — udev rule that triggers a re-attach. Create /etc/udev/rules.d/90-mtcp-guard-attach.rules:
text

ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/systemctl restart --no-block mtcp-guard-load.service"

The --no-block is important: udev runs RUN+ commands synchronously and will time out if the command blocks. --no-block tells systemd to queue the restart and return immediately.

A few caveats with this approach:

    Ordering. The udev add event fires when the kernel registers the netdevice, but the interface may not yet be UP or have an IP. install's ip link set … xdpgeneric works on a DOWN interface, so this is usually fine — the XDP hook is installed regardless. But if the driver isn't fully initialized when install runs, the attach can fail. In practice, RUN+= fires late enough that this is rarely an issue, but it can happen on slow USB devices.

    Recursion. Restarting mtcp-guard-load.service re-runs install, which enumerates all interfaces. That's a full re-attach pass, not just the new one. Fine for correctness, mildly wasteful.

    udev timeout. udev's default event_timeout is 180 seconds. systemctl restart --no-block returns immediately, so no timeout risk, but if you omit --no-block, the restart will block udev until install finishes (which includes bpftool prog load and the shape-verification loop — typically under a second, but not guaranteed).

Option C — udevadm trigger for a one-shot re-scan. If you've just added a udev rule or want to force udev to re-evaluate all netdevices without rebooting:
bash

sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=net --action=add

This is the standard way to make a newly-written udev rule take effect without a reboot . The --subsystem-match=net scopes the trigger to network devices only, avoiding a full system-wide re-scan. --action=add matches the rule's ACTION=="add" condition. --settle can be appended to wait for the triggered events to finish before returning, which is useful in scripts.

Option D — systemd udev unit instead of RUN+=. A cleaner alternative to a udev rule that restarts the whole loader: create a templated unit mtcp-guard-attach@.service:
ini

[Unit]
Description=Attach CVE-2026-98432 XDP guard to %I
After=sys-subsystem-net-devices-%i.device
BindsTo=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ip link set dev %i xdpgeneric pinned /sys/fs/bpf/cve_2026_98432_guard || true'

And the udev rule:
text

ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/systemctl start --no-block mtcp-guard-attach@%k.service"

%k in the udev rule expands to the kernel device name (the interface name). %i in the unit is the instance name. This is the systemd-native way to run a per-interface action on hotplug, avoids re-running the full loader, and scopes the work to the interface that appeared. The BindsTo= makes systemd tear the unit down when the device disappears, so the next appearance gets a fresh instance.

Option E — no automation, but a boot-time safety net. If you don't need hotplug support and only care about interfaces that exist at boot, the existing mtcp-guard-load.service already handles that. The interfaces on your box (enp2s0, wlp3s0, wlx000c4313decc) are all present at boot; the loader attaches to all of them. No udev work needed.

Recommendation: For a temporary mitigation on a fixed set of interfaces, Option E is sufficient — nothing to add. If you have hotplug-capable hardware and want automatic coverage, Option D is the cleanest: it's idempotent per interface, doesn't disturb existing attachments, and doesn't re-run the full loader on every udev event. Option B is a quick approximation if you don't want to write a template unit, but it re-runs install on every netdevice addition, which is noisier than necessary.

One final caution: do not depend on systemd-udev-settle.service to solve this. It is deprecated and can add significant boot time, and it only guarantees that udev has finished processing events that were queued at that moment — it does not wait for future hotplug events . The correct pattern for hotplug is the udev rule or the template unit above, not a settle dependency.
