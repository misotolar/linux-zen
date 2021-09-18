#!/bin/sh

CURPATH=$(cd "$(dirname "$0")" >/dev/null 2>&1;pwd -P)

rm -rf "$CURPATH/config" "$CURPATH/makepkg/linux-zen"
updpkgsums; BUILDDIR="$CURPATH/makepkg" makepkg -cfisr
