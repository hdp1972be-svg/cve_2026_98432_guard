#!/bin/bash
# Build statically-linked userspace binaries (no shared-library dependency).
# The eBPF object is built as usual; only the userspace side is static.
#
# Sources are read from ./src/. Binaries are written to ./out/static/.
#
# Notes on static linking:
#   - libbpf.a and libelf.a pull in zlib symbols (gzopen/gzgets for
#     reading /proc/config.gz, deflate/inflate for compressed ELF
#     sections). -lz must come after -lbpf -lelf on the link line.
#   - libpcap.a may not be available on every distro; if it's missing,
#     the daemon is built without pcap support (no -p flag).
#   - libsystemd.a may not be available; if it's missing, the daemon
#     falls back to syslog() instead of sd_journal_print().
#
# IMPORTANT: HAVE_SD_JOURNAL is a build-time decision, not a header
# auto-detection. The header <systemd/sd-journal.h> can be present
# (libsystemd-dev installed) while the static archive libsystemd.a is
# not linkable, or linkable but with unresolved transitive deps. If we
# set HAVE_SD_JOURNAL based on __has_include, the daemon emits
# sd_journal_print() calls that fail to link. So we only pass
# -DHAVE_SD_JOURNAL on the attempts that actually put -lsystemd on the
# link line.

set -euo pipefail

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC"

SRC_DIR="$SRC/src"
OUT_DIR="$SRC/out/static"

if [[ ! -d "$SRC_DIR" ]]; then
    echo "[-] source directory not found: $SRC_DIR" >&2
    exit 1
fi
mkdir -p "$OUT_DIR"

CC="${CC:-gcc}"

# Common static link line for both binaries.
COMMON_LIBS="-lbpf -lelf -lz"

# ---------------------------------------------------------------------------
# ctl
# ---------------------------------------------------------------------------
echo "[+] building static mtcp-guard-ctl"
"$CC" -O2 -Wall -Wextra -static \
    -o "$OUT_DIR/mtcp-guard-ctl" \
    "$SRC_DIR/mtcp-guard-ctl.c" \
    $COMMON_LIBS

# ---------------------------------------------------------------------------
# daemon
#
# Try combinations in order of decreasing feature coverage:
#   1. static + systemd + pcap
#   2. static + pcap (no systemd)
#   3. static + systemd (no pcap)
#   4. static only (syslog, no pcap)
#
# The first one that links wins. HAVE_SD_JOURNAL is passed only when
# -lsystemd is on the link line of that attempt.
# ---------------------------------------------------------------------------
echo "[+] building static mtcp-guardd"

DAEMON_SRC="$SRC_DIR/mtcp-guardd.c"
PCAP_SRC="$SRC_DIR/pcap_writer.c"
PCAP_HDR="$SRC_DIR/pcap_writer.h"
PCAP_AVAILABLE=0
SYSTEMD_AVAILABLE=0

if [[ -r "$PCAP_SRC" && -r "$PCAP_HDR" ]]; then
    PCAP_AVAILABLE=1
fi

if ls /usr/lib/*/libsystemd.a /usr/lib/libsystemd.a >/dev/null 2>&1; then
    SYSTEMD_AVAILABLE=1
fi

built=0

if (( PCAP_AVAILABLE && SYSTEMD_AVAILABLE )); then
    echo "    -> trying static + libsystemd + libpcap"
    if "$CC" -O2 -Wall -Wextra -static -I"$SRC_DIR" \
            -DHAVE_PCAP -DHAVE_SD_JOURNAL \
            -o "$OUT_DIR/mtcp-guardd" \
            "$DAEMON_SRC" "$PCAP_SRC" \
            $COMMON_LIBS -lpcap -lsystemd 2>/dev/null; then
        built=1
        echo "    -> linked with libsystemd (journald direct) and libpcap (-p enabled)"
    fi
fi

if (( !built && PCAP_AVAILABLE )); then
    echo "    -> trying static + libpcap (no libsystemd)"
    if "$CC" -O2 -Wall -Wextra -static -I"$SRC_DIR" \
            -DHAVE_PCAP \
            -o "$OUT_DIR/mtcp-guardd" \
            "$DAEMON_SRC" "$PCAP_SRC" \
            $COMMON_LIBS -lpcap 2>/dev/null; then
        built=1
        echo "    -> linked with libpcap (-p enabled), syslog() fallback for logging"
    fi
fi

if (( !built && SYSTEMD_AVAILABLE )); then
    echo "    -> trying static + libsystemd (no libpcap)"
    if "$CC" -O2 -Wall -Wextra -static \
            -DHAVE_SD_JOURNAL \
            -o "$OUT_DIR/mtcp-guardd" \
            "$DAEMON_SRC" \
            $COMMON_LIBS -lsystemd 2>/dev/null; then
        built=1
        echo "    -> linked with libsystemd, no pcap capture"
    fi
fi

if (( !built )); then
    echo "    -> trying static only (syslog fallback, no pcap)"
    "$CC" -O2 -Wall -Wextra -static \
        -o "$OUT_DIR/mtcp-guardd" \
        "$DAEMON_SRC" \
        $COMMON_LIBS
    echo "    -> linked with no libsystemd, no libpcap"
fi

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
echo "[+] verifying"
file "$OUT_DIR/mtcp-guard-ctl" "$OUT_DIR/mtcp-guardd"
for bin in mtcp-guard-ctl mtcp-guardd; do
    if file "$OUT_DIR/$bin" | grep -q "statically linked"; then
        echo "  $bin: statically linked (confirmed by file)"
    else
        echo "  $bin: NOT statically linked — check $OUT_DIR/$bin" >&2
    fi
done

# ---------------------------------------------------------------------------
# checksums
# ---------------------------------------------------------------------------
( cd "$OUT_DIR" && sha256sum mtcp-guard-ctl mtcp-guardd > SHA256SUMS )
echo "[+] wrote $OUT_DIR/SHA256SUMS"
