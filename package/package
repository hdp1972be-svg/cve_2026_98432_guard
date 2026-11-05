#!/usr/bin/env bash
# ============================================================================
# package.sh
#
# Produce distributable artifacts from the built tree:
#
#   1. cve-2026-98432-guard-<ver>-src.tar.gz
#        source tarball (git archive, or tar of the source tree)
#
#   2. cve-2026-98432-guard_<ver>_amd64.deb
#        Debian package, glibc-static binaries (from ./out/static/)
#
#   3. cve-2026-98432-guard-musl_<ver>_amd64.deb
#        Debian package, musl-static binaries (from ./out/zig/x86_64-linux-musl/)
#        Installs the same files, but the daemon and ctl are musl-static.
#
#   4. cve-2026-98432-guard-musl-<ver>-x86_64.tar.gz
#        Plain tarball for embedded targets without dpkg.
#
# The kernel-specific .o files are picked from the repo root and included
# in every artifact, one per kernel ABI class. The install script (already
# kernel-aware) selects the right one at install time.
# ============================================================================

set -euo pipefail

if [[ -t 1 ]]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
    B='\033[0;34m'; C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
fi

ok()   { printf "${G}[OK]${N}   %s\n" "$*"; }
warn() { printf "${Y}[WARN]${N} %s\n" "$*"; }
info() { printf "${B}[INFO]${N} %s\n" "$*"; }
err()  { printf "${R}[ERR]${N}  %s\n" "$*" >&2; }

SRC_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC_ROOT"

# Version: from git tag, or fallback to date-based.
if git rev-parse --git-dir >/dev/null 2>&1; then
    if VERSION="$(git describe --tags --always 2>/dev/null)"; then
        VERSION="${VERSION#v}"
    else
        VERSION="$(date +%Y%m%d)-$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
    fi
else
    VERSION="$(date +%Y%m%d)-nogit"
fi
info "version: $VERSION"

# Architecture of the glibc-static build (from ./out/static/).
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64)  DEB_ARCH="amd64" ;;
    aarch64) DEB_ARCH="arm64" ;;
    *) err "unsupported host arch: $HOST_ARCH"; exit 1 ;;
esac
info "host arch: $HOST_ARCH (deb: $DEB_ARCH)"

# Locate the kernel-specific .o files in the repo root.
shopt -s nullglob
KO_FILES=( cve_2026_98432_guard-k*.o )
shopt -u nullglob
if (( ${#KO_FILES[@]} == 0 )); then
    err "no kernel-specific .o files found in $SRC_ROOT"
    err "run ./build --kernel X.Y for each target kernel first"
    exit 1
fi
info "kernel-specific .o files: ${KO_FILES[*]}"

# The install / remove / install-service scripts and service files.
REQUIRED_SCRIPTS=( install remove install-service )
for s in "${REQUIRED_SCRIPTS[@]}"; do
    [[ -r "$s" ]] || { err "missing script: $s"; exit 1; }
done

# Optional components.
OPTIONAL_FILES=()
for f in README.md DISCLAIMER LICENSE whitelist.conf; do
    [[ -f "$f" ]] && OPTIONAL_FILES+=("$f")
done

# Service / udev files: embedded by install-service, but we also ship them
# as reference copies in the package.
for f in services/*.service services/*.conf; do
    [[ -f "$f" ]] || continue
done

OUT_DIR="$SRC_ROOT/out/dist"
mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# 1. Source tarball
# ---------------------------------------------------------------------------
echo
info "producing source tarball"

SRC_NAME="cve-2026-98432-guard-${VERSION}-src"
SRC_TAR="$OUT_DIR/${SRC_NAME}.tar.gz"

if git rev-parse --git-dir >/dev/null 2>&1; then
    git archive --format=tar.gz --prefix="$SRC_NAME/" -o "$SRC_TAR" HEAD
else
    # No git: tar the current tree, excluding build artifacts.
    tar --exclude='./out' \
        --exclude='./cve_2026_98432_guard*.o' \
        --exclude='./mtcp-guardd' \
        --exclude='./mtcp-guard-ctl' \
        --exclude='./xdp_option_probe' \
        --exclude='./.git' \
        -czf "$SRC_TAR" \
        --transform "s|^\\./|${SRC_NAME}/|" \
        .
fi
ok "source: $SRC_TAR"

# ---------------------------------------------------------------------------
# 2. Debian package, glibc-static
# ---------------------------------------------------------------------------
echo
info "producing Debian package (glibc-static)"

if [[ ! -x "out/static/mtcp-guardd" ]] || [[ ! -x "out/static/mtcp-guard-ctl" ]]; then
    warn "out/static/ binaries missing; run ./build-portable first"
    warn "skipping glibc-static .deb"
else
    PKG_NAME="cve-2026-98432-guard"
    PKG_DIR="$OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}"

    rm -rf "$PKG_DIR"
    mkdir -p "$PKG_DIR/DEBIAN"
    mkdir -p "$PKG_DIR/usr/bin"
    mkdir -p "$PKG_DIR/etc/cve-2026-98432-guard"
    mkdir -p "$PKG_DIR/lib/systemd/system"
    mkdir -p "$PKG_DIR/lib/udev/rules.d"

    install -m 0755 out/static/mtcp-guard-ctl "$PKG_DIR/usr/bin/"
    install -m 0755 out/static/mtcp-guardd    "$PKG_DIR/usr/bin/"

    install -m 0755 install          "$PKG_DIR/etc/cve-2026-98432-guard/"
    install -m 0755 remove           "$PKG_DIR/etc/cve-2026-98432-guard/"
    install -m 0755 install-service  "$PKG_DIR/etc/cve-2026-98432-guard/"

    for ko in "${KO_FILES[@]}"; do
        install -m 0644 "$ko" "$PKG_DIR/etc/cve-2026-98432-guard/"
    done

    if [[ -f whitelist.conf ]]; then
        install -m 0644 whitelist.conf "$PKG_DIR/etc/cve-2026-98432-guard/"
    fi
    for f in README.md DISCLAIMER LICENSE; do
        [[ -f "$f" ]] && install -m 0644 "$f" "$PKG_DIR/etc/cve-2026-98432-guard/"
    done

    # systemd units and udev rule: written by install-service at run time,
    # but shipped here as reference copies under /usr/share/doc.
    mkdir -p "$PKG_DIR/usr/share/doc/$PKG_NAME"
    install -m 0644 services/mtcp-guard-load.service \
        "$PKG_DIR/usr/share/doc/$PKG_NAME/" 2>/dev/null || true
    install -m 0644 services/mtcp-guardd.service \
        "$PKG_DIR/usr/share/doc/$PKG_NAME/" 2>/dev/null || true

    # control file
    INSTALLED_SIZE="$(du -sk "$PKG_DIR" | cut -f1)"
    cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Installed-Size: $INSTALLED_SIZE
Depends: libc6, bpftool, iproute2
Recommends: libpcap0.8
Maintainer: i <i@localhost>
Description: CVE-2026-98432 XDP mitigation, detection and capture
 The CVE-2026-98432 XDP guard drops IPv4/TCP packets with IPv4
 options at the XDP hook, logs every drop to journald, and writes
 the dropped packets to a pcap for forensic analysis.
 .
 This package installs glibc-static userspace binaries, one eBPF
 object per kernel ABI class, and the install/remove/install-service
 scripts. Run 'install-service' after installation to enable the
 systemd units and the udev hotplug rule.
EOF

    cat > "$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Do not auto-install the guard: attach it with install-service, so the
# operator chooses whether to enable it now.
echo "cve-2026-98432-guard installed."
echo "Run 'sudo /etc/cve-2026-98432-guard/install-service' to enable the"
echo "loader, the daemon and the udev hotplug rule."
exit 0
EOF
    chmod 0755 "$PKG_DIR/DEBIAN/postinst"

    cat > "$PKG_DIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# Detach the guard and unpin everything before the package files go away.
if [ -x /etc/cve-2026-98432-guard/remove ]; then
    /etc/cve-2026-98432-guard/remove || true
fi
# Stop and disable the units if they exist.
systemctl stop mtcp-guardd.service 2>/dev/null || true
systemctl stop mtcp-guard-load.service 2>/dev/null || true
systemctl disable mtcp-guardd.service 2>/dev/null || true
systemctl disable mtcp-guard-load.service 2>/dev/null || true
exit 0
EOF
    chmod 0755 "$PKG_DIR/DEBIAN/prerm"

    dpkg-deb --build --root-owner-group "$PKG_DIR" \
        "$OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
    ok "deb (glibc-static): $OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
fi

# ---------------------------------------------------------------------------
# 3. Debian package, musl-static (embedded)
# ---------------------------------------------------------------------------
echo
info "producing Debian package (musl-static)"

MUSL_DIR="out/zig/x86_64-linux-musl"
if [[ "$HOST_ARCH" == "aarch64" ]]; then
    MUSL_DIR="out/zig/aarch64-linux-musl"
fi

if [[ ! -x "$MUSL_DIR/mtcp-guardd" ]] || [[ ! -x "$MUSL_DIR/mtcp-guard-ctl" ]]; then
    warn "$MUSL_DIR binaries missing; run ./build-zig-alpine first"
    warn "skipping musl-static .deb"
else
    PKG_NAME="cve-2026-98432-guard-musl"
    PKG_DIR="$OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}"

    rm -rf "$PKG_DIR"
    mkdir -p "$PKG_DIR/DEBIAN"
    mkdir -p "$PKG_DIR/usr/bin"
    mkdir -p "$PKG_DIR/etc/cve-2026-98432-guard"
    mkdir -p "$PKG_DIR/usr/share/doc/$PKG_NAME"

    install -m 0755 "$MUSL_DIR/mtcp-guard-ctl" "$PKG_DIR/usr/bin/"
    install -m 0755 "$MUSL_DIR/mtcp-guardd"    "$PKG_DIR/usr/bin/"

    install -m 0755 install          "$PKG_DIR/etc/cve-2026-98432-guard/"
    install -m 0755 remove           "$PKG_DIR/etc/cve-2026-98432-guard/"
    install -m 0755 install-service  "$PKG_DIR/etc/cve-2026-98432-guard/"

    for ko in "${KO_FILES[@]}"; do
        install -m 0644 "$ko" "$PKG_DIR/etc/cve-2026-98432-guard/"
    done

    [[ -f whitelist.conf ]] && \
        install -m 0644 whitelist.conf "$PKG_DIR/etc/cve-2026-98432-guard/"
    for f in README.md DISCLAIMER LICENSE; do
        [[ -f "$f" ]] && install -m 0644 "$f" "$PKG_DIR/etc/cve-2026-98432-guard/"
    done

    INSTALLED_SIZE="$(du -sk "$PKG_DIR" | cut -f1)"
    cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Installed-Size: $INSTALLED_SIZE
Depends: bpftool, iproute2
Maintainer: i <i@localhost>
Description: CVE-2026-98432 XDP mitigation, detection and capture (musl)
 Same as cve-2026-98432-guard, but the userspace daemon and control
 utility are musl-static binaries. They run on any Linux host without
 requiring a matching glibc, which makes this variant suitable for
 embedded systems, appliances and minimal root filesystems.
EOF

    # Same postinst and prerm as the glibc package.
    cat > "$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
echo "cve-2026-98432-guard-musl installed."
echo "Run 'sudo /etc/cve-2026-98432-guard/install-service' to enable the"
echo "loader, the daemon and the udev hotplug rule."
exit 0
EOF
    chmod 0755 "$PKG_DIR/DEBIAN/postinst"

    cat > "$PKG_DIR/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -x /etc/cve-2026-98432-guard/remove ]; then
    /etc/cve-2026-98432-guard/remove || true
fi
systemctl stop mtcp-guardd.service 2>/dev/null || true
systemctl stop mtcp-guard-load.service 2>/dev/null || true
systemctl disable mtcp-guardd.service 2>/dev/null || true
systemctl disable mtcp-guard-load.service 2>/dev/null || true
exit 0
EOF
    chmod 0755 "$PKG_DIR/DEBIAN/prerm"

    dpkg-deb --build --root-owner-group "$PKG_DIR" \
        "$OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
    ok "deb (musl-static): $OUT_DIR/${PKG_NAME}_${VERSION}_${DEB_ARCH}.deb"
fi

# ---------------------------------------------------------------------------
# 4. Plain tarball with musl-static binaries (embedded, no dpkg)
# ---------------------------------------------------------------------------
echo
info "producing musl-static tarball (embedded)"

if [[ -x "$MUSL_DIR/mtcp-guardd" ]] && [[ -x "$MUSL_DIR/mtcp-guard-ctl" ]]; then
    TAR_NAME="cve-2026-98432-guard-musl-${VERSION}-${HOST_ARCH}"
    TAR_DIR="$OUT_DIR/$TAR_NAME"

    rm -rf "$TAR_DIR"
    mkdir -p "$TAR_DIR"

    install -m 0755 "$MUSL_DIR/mtcp-guard-ctl" "$TAR_DIR/"
    install -m 0755 "$MUSL_DIR/mtcp-guardd"    "$TAR_DIR/"
    install -m 0755 install          "$TAR_DIR/"
    install -m 0755 remove           "$TAR_DIR/"
    install -m 0755 install-service  "$TAR_DIR/"
    for ko in "${KO_FILES[@]}"; do
        install -m 0644 "$ko" "$TAR_DIR/"
    done
    [[ -f whitelist.conf ]] && install -m 0644 whitelist.conf "$TAR_DIR/"
    for f in README.md DISCLAIMER LICENSE; do
        [[ -f "$f" ]] && install -m 0644 "$f" "$TAR_DIR/"
    done

    ( cd "$OUT_DIR" && tar -czf "${TAR_NAME}.tar.gz" "$TAR_NAME" )
    rm -rf "$TAR_DIR"
    ok "tarball (musl-static): $OUT_DIR/${TAR_NAME}.tar.gz"
else
    warn "$MUSL_DIR binaries missing; skipping musl-static tarball"
fi

# ---------------------------------------------------------------------------
# 5. Checksums
# ---------------------------------------------------------------------------
echo
info "generating checksums"
( cd "$OUT_DIR" && sha256sum \
    cve-2026-98432-guard-* \
    > SHA256SUMS )
ok "checksums: $OUT_DIR/SHA256SUMS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
printf "${BOLD}${G}PACKAGING COMPLETE${N}\n"
ls -la "$OUT_DIR" | grep -v '^total' | sed 's/^/  /'
echo
info "version:      $VERSION"
info "arch:         $DEB_ARCH"
info "kernel .o's:  ${KO_FILES[*]}"
