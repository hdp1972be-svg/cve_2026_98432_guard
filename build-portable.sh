#!/bin/bash
# Build statically-linked userspace binaries (no shared-library dependency).
# The eBPF object is built as usual; only the userspace side is static.

set -euo pipefail

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SRC"

CC="${CC:-gcc}"
mkdir -p out/static

echo "[+] building static mtcp-guard-ctl"
"$CC" -O2 -Wall -Wextra -static -o out/static/mtcp-guard-ctl \
    mtcp-guard-ctl.c -lbpf -lelf

echo "[+] building static mtcp-guardd"
if "$CC" -O2 -Wall -Wextra -static -o out/static/mtcp-guardd \
        mtcp-guardd.c -lbpf -lelf -lsystemd 2>/dev/null; then
    echo "    -> linked with libsystemd (journald direct)"
else
    echo "    [!] libsystemd.a not available; falling back to syslog"
    echo "    [!] check: ls /usr/lib/*/libsystemd.a"
    "$CC" -O2 -Wall -Wextra -static -o out/static/mtcp-guardd \
        mtcp-guardd.c -lbpf -lelf
fi

echo "[+] verifying"
file out/static/mtcp-guard-ctl out/static/mtcp-guardd
ldd out/static/mtcp-guard-ctl  2>&1 | head -1
ldd out/static/mtcp-guardd     2>&1 | head -1

sha256sum out/static/* > out/static/SHA256SUMS
