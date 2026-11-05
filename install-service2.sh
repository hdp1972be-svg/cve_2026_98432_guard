#!/bin/bash
#
# install-service
#
# Install the systemd units and udev rule for the CVE-2026-98432 XDP
# guard, deploy the whitelist, and enable both the loader and the
# daemon.
#
# This script writes the unit files inline (heredocs) rather than
# reading them from ./services/. The reason is portability: the units
# reference paths that are fixed at the package level, and keeping
# them inline means one file to deploy instead of five.
#
# The guard object is named after the target kernel:
#     cve_2026_98432_guard-k<major>.<minor>.o
# so multiple kernel versions can coexist in /etc/cve-2026-98432-guard/.
# The sanity check below resolves the running kernel version and looks
# for the matching object.
#
# Run once after ./build && sudo ./install. Requires root.
# Idempotent: safe to run repeatedly.

set -euo pipefail

# --- paths ---------------------------------------------------------------
GUARD_DIR="/etc/cve-2026-98432-guard"
UNIT_DIR="/etc/systemd/system"
UDEV_DIR="/etc/udev/rules.d"

LOADER_UNIT="mtcp-guard-load.service"
DAEMON_UNIT="mtcp-guardd.service"
UDEV_RULE="90-mtcp-guard-attach.rules"
SYSTEMD_BPF_MOUNT="sys-fs-bpf.mount"

# --- resolve the kernel-specific object ----------------------------------
KERNEL_MM="$(uname -r | sed -nE 's/^([0-9]+)\.([0-9]+).*/\1.\2/p')"
if [[ -z "$KERNEL_MM" ]]; then
    echo "[-] could not parse running kernel version from uname -r" >&2
    exit 1
fi

OBJECT="$GUARD_DIR/cve_2026_98432_guard-k${KERNEL_MM}.o"

if [[ ! -r "$OBJECT" ]]; then
    echo "[-] no guard object for running kernel $KERNEL_MM" >&2
    echo "    expected: $OBJECT" >&2
    echo "    available in $GUARD_DIR:" >&2
    ls -1 "$GUARD_DIR"/cve_2026_98432_guard-k*.o 2>/dev/null \
        | sed 's/^/      /' >&2 || echo "      (none)" >&2
    echo "    run ./build --kernel $KERNEL_MM && sudo ./install first." >&2
    exit 1
fi

if [[ ! -x "$GUARD_DIR/install" ]]; then
    echo "[-] $GUARD_DIR/install not found or not executable." >&2
    echo "    run ./build && sudo ./install first." >&2
    exit 1
fi

if [[ ! -x "$GUARD_DIR/mtcp-guardd" ]]; then
    echo "[-] $GUARD_DIR/mtcp-guardd not found or not executable." >&2
    echo "    run ./build && sudo ./install first." >&2
    exit 1
fi

echo "[+] running kernel: $KERNEL_MM"
echo "[+] guard object:   $OBJECT"

# --- ensure bpffs is mounted now, and by systemd at boot -----------------
echo "[+] ensuring $SYSTEMD_BPF_MOUNT exists"
sudo tee "$UNIT_DIR/$SYSTEMD_BPF_MOUNT" >/dev/null <<'EOF'
[Unit]
Description=BPF filesystem
Documentation=man:mount(8)
DefaultDependencies=no
Before=local-fs.target
After=systemd-remount-fs.service
ConditionPathExists=/sys/fs

[Mount]
What=bpf
Where=/sys/fs/bpf
Type=bpf
Options=rw,nosuid,nodev,noexec,relatime,mode=700
EOF

# --- loader unit ---------------------------------------------------------
echo "[+] writing $LOADER_UNIT"
sudo tee "$UNIT_DIR/$LOADER_UNIT" >/dev/null <<'EOF'
[Unit]
Description=CVE-2026-98432 IPv4 TCP Options XDP Guard
Documentation=file:/etc/cve-2026-98432-guard/README.md
Wants=systemd-udev-settle.service
After=systemd-udev-settle.service
Before=network.target
Wants=sys-fs-bpf.mount
After=sys-fs-bpf.mount

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/etc/cve-2026-98432-guard
ExecStartPre=/usr/bin/test -d /etc/cve-2026-98432-guard
ExecStartPre=/usr/bin/test -x /etc/cve-2026-98432-guard/install
ExecStart=/etc/cve-2026-98432-guard/install
TimeoutStartSec=60
TimeoutStopSec=30
Restart=no

[Install]
WantedBy=multi-user.target
EOF

# --- daemon unit ---------------------------------------------------------
echo "[+] writing $DAEMON_UNIT"
sudo tee "$UNIT_DIR/$DAEMON_UNIT" >/dev/null <<'EOF'
[Unit]
Description=CVE-2026-98432 IPv4 TCP Options XDP Guard (event daemon)
Documentation=file:/etc/cve-2026-98432-guard/README.md
Requires=mtcp-guard-load.service
After=mtcp-guard-load.service
ConditionPathExists=/sys/fs/bpf/cve_2026_98432_events

[Service]
Type=simple
ExecStart=/etc/cve-2026-98432-guard/mtcp-guardd
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s

LogRateLimitIntervalSec=30
LogRateLimitBurst=5000

RuntimeDirectory=mtcp-guardd
RuntimeDirectoryMode=0755

StandardOutput=journal
StandardError=journal

NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/sys/fs/bpf /run

[Install]
WantedBy=multi-user.target
EOF

# --- udev rule -----------------------------------------------------------
echo "[+] writing $UDEV_RULE"
sudo tee "$UDEV_DIR/$UDEV_RULE" >/dev/null <<'EOF'
# Re-run the CVE-2026-98432 XDP guard loader when a network interface
# appears. The loader is idempotent: it skips interfaces that already
# have the guard attached and only attaches to the new one.
ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/systemctl restart --no-block mtcp-guard-load.service"
EOF

# --- deploy whitelist if absent ------------------------------------------
if [[ -f "$GUARD_DIR/whitelist.conf" ]]; then
    echo "[+] $GUARD_DIR/whitelist.conf already exists; leaving it untouched"
fi

# --- reload systemd + udev -----------------------------------------------
echo "[+] systemctl daemon-reload"
sudo systemctl daemon-reload

echo "[+] udevadm control --reload-rules"
sudo udevadm control --reload-rules || true

sudo systemctl reset-failed "$LOADER_UNIT" 2>/dev/null || true
sudo systemctl reset-failed "$DAEMON_UNIT" 2>/dev/null || true
sudo systemctl reset-failed "$SYSTEMD_BPF_MOUNT" 2>/dev/null || true

# If a previous install created a *stale* mount unit at a different
# path (from an earlier version), remove it so it doesn't shadow the
# new one.
sudo rm -f /etc/systemd/system/sys-fs-bpf.mount.service 2>/dev/null || true
sudo systemctl daemon-reload

# --- enable bpffs mount unit (best-effort) -------------------------------
echo "[+] starting $SYSTEMD_BPF_MOUNT (best-effort)"
if ! sudo systemctl start "$SYSTEMD_BPF_MOUNT" 2>/dev/null; then
    echo "[!] systemd could not start $SYSTEMD_BPF_MOUNT."
    echo "    Modern systemd may reject manually-provided API filesystem"
    echo "    mount units. The loader's install script mounts bpffs itself,"
    echo "    so this is not fatal."
fi

if mountpoint -q /sys/fs/bpf; then
    echo "[+] /sys/fs/bpf is mounted"
else
    echo "[!] /sys/fs/bpf not mounted yet; the loader will mount it"
fi

# --- loader --------------------------------------------------------------
echo "[+] enabling and starting $LOADER_UNIT"
if ! sudo systemctl enable --now "$LOADER_UNIT"; then
    echo "[-] failed to start $LOADER_UNIT" >&2
    echo "    Inspect with: journalctl -u $LOADER_UNIT --no-pager" >&2
    exit 1
fi

if ! sudo test -e /sys/fs/bpf/cve_2026_98432_events; then
    echo "[-] events map not pinned after loader start." >&2
    echo "    Check: journalctl -u $LOADER_UNIT --no-pager" >&2
    echo "    Check: sudo ls -la /sys/fs/bpf/" >&2
    exit 1
fi

# --- daemon --------------------------------------------------------------
echo "[+] enabling and starting $DAEMON_UNIT"
if ! sudo systemctl enable --now "$DAEMON_UNIT"; then
    echo "[-] failed to start $DAEMON_UNIT" >&2
    echo "    Inspect with: journalctl -u $DAEMON_UNIT --no-pager" >&2
    exit 1
fi

# --- status --------------------------------------------------------------
echo
echo "[+] systemctl status:"
sudo systemctl --no-pager --lines=0 status \
    "$LOADER_UNIT" "$DAEMON_UNIT" || true

echo
echo "[+] done. To verify the guard is live:"
echo "    sudo $GUARD_DIR/mtcp-guard-ctl stats"
echo "    journalctl -u $DAEMON_UNIT -f"
echo
echo "[+] udev rule installed: $UDEV_DIR/$UDEV_RULE"
echo "    Network interfaces added after boot will be attached automatically"
echo "    by re-running the loader unit. Check with:"
echo "    journalctl -u $LOADER_UNIT -f"
