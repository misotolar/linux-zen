#!/bin/sh

CURPATH=$(cd "$(dirname "$0")" >/dev/null 2>&1;pwd -P)

rm -rf "$CURPATH/makepkg/linux-zen"
BUILDDIR="$CURPATH/makepkg" makepkg -cfisr
