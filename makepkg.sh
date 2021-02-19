#!/bin/sh

BUILDDIR="$(cd "$(dirname "$0")" >/dev/null 2>&1;pwd -P)/tmp" makepkg -fsir
