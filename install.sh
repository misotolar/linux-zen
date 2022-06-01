#!/bin/sh

if [ -s /sys/firmware/acpi/platform_profile_choices ]; then
    echo $(grep -oE '[^[:space:]]+$' /sys/firmware/acpi/platform_profile_choices) | sudo tee /sys/firmware/acpi/platform_profile > /dev/null
fi

CURPATH=$(cd "$(dirname "$0")" >/dev/null 2>&1;pwd -P)

rm -rf "$CURPATH"/config "$CURPATH"/01*.patch "$CURPATH"/makepkg/linux-zen
updpkgsums; BUILDDIR="$CURPATH/makepkg" _LTO_CLANG="FULL" makepkg -cfisr
