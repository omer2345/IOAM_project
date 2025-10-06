#!/bin/bash
# Build tracepath from IOAM_project/tools/iputils_ioam

set -e

echo ">>> Entering tools/iputils_ioam"
cd tools/iputils_ioam

echo ">>> Building tracepath with ninja..."
ninja -C build tracepath

echo ">>> Returning to project root"
cd ../..

echo ">>> Done. Binary is at: tools/iputils_ioam/build/tracepath"