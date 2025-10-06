#!/bin/bash

NS=123
DEV="veth0"
PREFIX="db04::/64"

echo "Testing IOAM trace-type bits (1 at a time)..."

for i in {0..15}; do
    bitmask=$((1 << i))
    printf -v hex "0x%04x" "$bitmask"

    echo -n "Trying trace type $hex: "
    if ip -6 route add "$PREFIX" encap ioam6 mode inline trace prealloc type "$hex" ns $NS size 64 dev $DEV 2>/dev/null; then
        echo "V accepted"
        ip -6 route del "$PREFIX" dev $DEV 2>/dev/null
    else
        echo "X rejected"
    fi
done