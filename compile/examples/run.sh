#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
P4C_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$P4C_DIR/build"

# Input P4 program
P4_PROG="$SCRIPT_DIR/load_balancer.p4"

# Output directories
mkdir -p "$SCRIPT_DIR/out_dpdk"
mkdir -p "$SCRIPT_DIR/out_ubpf"

echo "Compiling with DPDK backend..."
"$BUILD_DIR/p4c-dpdk" "$P4_PROG" -o "$SCRIPT_DIR/out_dpdk/load_balancer.spec" --arch psa

echo "Compiling with uBPF backend..."
"$BUILD_DIR/p4c-ubpf" "$P4_PROG" -o "$SCRIPT_DIR/out_ubpf/load_balancer.c" --arch psa

echo "Done!" 