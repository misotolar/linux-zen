#!/bin/sh

rm -rf "$PWD"/{makepkg,01*.patch,config,auto-cpu-optimization.sh}
updpkgsums; makepkg --printsrcinfo > .SRCINFO; BUILDDIR="$PWD/makepkg" _LTO_CLANG="FULL" makepkg -cfisr
