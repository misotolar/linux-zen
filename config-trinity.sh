#!/bin/sh

sed -i 's/CONFIG_GENERIC_CPU=y/# CONFIG_GENERIC_CPU is not set/' .config
sed -i 's/# CONFIG_MSKYLAKE is not set/CONFIG_MSKYLAKE=y\nCONFIG_X86_P6_NOP=y/' .config

sed -i 's/CONFIG_HZ_1000=y/# CONFIG_HZ_1000 is not set/' .config
sed -i 's/# CONFIG_HZ_300 is not set/CONFIG_HZ_300=y/' .config
sed -i 's/CONFIG_HZ=1000/CONFIG_HZ=300/' .config

# General setup
scripts/config --set-str DEFAULT_HOSTNAME "trinity"
scripts/config --disable SECURITY_APPARMOR --disable AUDIT

# Processor type and features
scripts/config --disable X86_AMD_PLATFORM_DEVICE
scripts/config --disable HYPERVISOR_GUEST
scripts/config --disable CPU_SUP_HYGON --disable CPU_SUP_CENTAUR --disable CPU_SUP_ZHAOXIN --disable CPU_SUP_AMD
scripts/config --disable GART_IOMMU --disable X86_MCE_AMD --disable MICROCODE_AMD --disable MICROCODE_OLD_INTERFACE --disable AMD_MEM_ENCRYPT
scripts/config --disable NUMA

# Enable loadable module support
scripts/config --enable MODULE_SIG_FORCE

# Device Drivers
scripts/config --disable WATCHDOG

# Device Drivers - IOMMU Support
scripts/config --disable AMD_IOMMU

# Device Drivers - Graphic support
scripts/config --disable VGA_SWITCHEROO

# Security options
scripts/config --disable SECURITY_SELINUX --disable SECURITY_TOMOYO --disable SECURITY_YAMA

# https://bugs.archlinux.org/task/69479
scripts/config --disable CONFIG_XZ_DEC_POWERPC --disable CONFIG_XZ_DEC_IA64 --disable CONFIG_XZ_DEC_ARM --disable CONFIG_XZ_DEC_ARMTHUMB --disable CONFIG_XZ_DEC_SPARC

# https://bugs.archlinux.org/task/67614
scripts/config --disable CONFIG_ASHMEM --disable CONFIG_ANDROID