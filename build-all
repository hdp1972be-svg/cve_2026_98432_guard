#!/bin/bash

# Eenmalig: build alles
./build                                    # kernel-specifieke .o + userspace
./build --kernel 4.18 --legacy-maps        # als je ook 4.18 wil ondersteunen
./build --kernel 5.10                      # BTF-variant voor 5.3+
./build-portable                           # glibc-static binaries
sudo ./build-zig-alpine --make-sysroot     # musl sysroot (eenmalig)
./build-zig-alpine                         # musl-static binaries

# Dan verpakken:
./package.sh
