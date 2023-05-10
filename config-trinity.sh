#!/bin/sh

EXTRA_FIRMWARE_DIR="$(mktemp -d)";
EXTRA_FIRMWARE_STR=""
EXTRA_FIRMWARE=(
    amdgpu/picasso_asd.bin
    amdgpu/picasso_ce.bin
    amdgpu/picasso_gpu_info.bin
    amdgpu/picasso_me.bin
    amdgpu/picasso_mec.bin
    amdgpu/picasso_mec2.bin
    amdgpu/picasso_pfp.bin
    amdgpu/picasso_rlc.bin
    amdgpu/picasso_sdma.bin
    amdgpu/picasso_ta.bin
    amdgpu/picasso_vcn.bin
    amdgpu/raven_dmcu.bin
)

for BLOB in "${EXTRA_FIRMWARE[@]}"; do
    EXTRA_FIRMWARE_STR="${EXTRA_FIRMWARE_STR} ${BLOB}"
    mkdir -p "${EXTRA_FIRMWARE_DIR}/$(dirname ${BLOB})"
    cp -v "/lib/firmware/${BLOB}.xz" "${EXTRA_FIRMWARE_DIR}/${BLOB}.xz"
    xz -d "${EXTRA_FIRMWARE_DIR}/${BLOB}.xz"
done

# Cleanup
scripts/config \
    -d BOOTTIME_TRACING \
    -d BOOT_CONFIG \
    -d BLK_DEV_INITRD

# Firmware
scripts/config --set-str EXTRA_FIRMWARE "${EXTRA_FIRMWARE_STR}"
scripts/config --set-str EXTRA_FIRMWARE_DIR "${EXTRA_FIRMWARE_DIR}"

# Drivers
scripts/config \
    -e BLK_DEV_NVME \
    -e DRM_AMDGPU

# Filesystems
scripts/config \
    -e EXT4_FS \
    -e VFAT_FS
