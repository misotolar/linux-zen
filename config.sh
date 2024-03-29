#!/bin/sh

### Hostname
scripts/config \
    --set-str DEFAULT_HOSTNAME "$KBUILD_BUILD_HOST"

### RCU priority
scripts/config \
    --set-val RCU_BOOST_DELAY 331

### CPU scheduler
scripts/config \
    -e SCHED_ALT \
    -e SCHED_PDS \
    -d SCHED_BMQ

### LLVM level
scripts/config \
    -e LTO \
    -e LTO_CLANG \
    -e ARCH_SUPPORTS_LTO_CLANG \
    -e ARCH_SUPPORTS_LTO_CLANG_THIN \
    -d LTO_NONE \
    -e HAS_LTO_CLANG \
    -e HAVE_GCC_PLUGINS \
    -e "LTO_CLANG_${_LTO_CLANG:-THIN}"

### Tick rate
scripts/config \
    -d HZ_1000 \
    -e "HZ_${_HZ:-1000}" \
    --set-val HZ ${_HZ:-1000}

### PSI
scripts/config \
    -d PSI

### NUMA
scripts/config \
    -d NUMA \
    -d AMD_NUMA \
    -d X86_64_ACPI_NUMA \
    -d NODES_SPAN_OTHER_NODES \
    -d NUMA_EMU \
    -d USE_PERCPU_NUMA_NODE_ID \
    -d ACPI_NUMA \
    -d ARCH_SUPPORTS_NUMA_BALANCING \
    -d NODES_SHIFT \
    -u NODES_SHIFT \
    -d NEED_MULTIPLE_NODES \
    -d NUMA_BALANCING \
    -d NUMA_BALANCING_DEFAULT_ENABLED

### Maximum number of CPUs
if [[ "archlinux" != "$KBUILD_BUILD_HOST" ]]; then
    scripts/config \
        --set-val NR_CPUS $(($(nproc)*2))
fi

### I/O schedulers
scripts/config \
    -d MQ_IOSCHED_KYBER

### Performance governor
scripts/config \
    -d CPU_FREQ_DEFAULT_GOV_SCHEDUTIL \
    -e CPU_FREQ_DEFAULT_GOV_PERFORMANCE

### TCP congestion control
scripts/config \
    -d DEFAULT_CUBIC \
    -d TCP_CONG_BIC \
    -d TCP_CONG_CUBIC \
    -d TCP_CONG_WESTWOOD \
    -d TCP_CONG_HTCP \
    -d TCP_CONG_HSTCP \
    -d TCP_CONG_HYBLA \
    -d TCP_CONG_VEGAS \
    -d TCP_CONG_NV \
    -d TCP_CONG_SCALABLE \
    -d TCP_CONG_LP \
    -d TCP_CONG_VENO \
    -d TCP_CONG_YEAH \
    -d TCP_CONG_ILLINOIS \
    -d TCP_CONG_DCTCP \
    -d TCP_CONG_CDG \
    -d TCP_CONG_BBR \
    -e TCP_CONG_BBR2 \
    -e DEFAULT_BBR2 \
    --set-str DEFAULT_TCP_CONG bbr2

### LRNG
scripts/config \
    -d RANDOM_DEFAULT_IMPL \
    -e LRNG \
    -e LRNG_SHA256 \
    -e LRNG_COMMON_DEV_IF \
    -e LRNG_DRNG_ATOMIC \
    -e LRNG_SYSCTL \
    -e LRNG_RANDOM_IF \
    -e LRNG_AIS2031_NTG1_SEEDING_STRATEGY \
    -m LRNG_KCAPI_IF \
    -m LRNG_HWRAND_IF \
    -e LRNG_DEV_IF \
    -e LRNG_RUNTIME_ES_CONFIG \
    -e LRNG_IRQ_DFLT_TIMER_ES \
    -d LRNG_SCHED_DFLT_TIMER_ES \
    -e LRNG_TIMER_COMMON \
    -d LRNG_COLLECTION_SIZE_256 \
    -d LRNG_COLLECTION_SIZE_512 \
    -e LRNG_COLLECTION_SIZE_1024 \
    -d LRNG_COLLECTION_SIZE_2048 \
    -d LRNG_COLLECTION_SIZE_4096 \
    -d LRNG_COLLECTION_SIZE_8192 \
    --set-val LRNG_COLLECTION_SIZE 1024 \
    -e LRNG_HEALTH_TESTS \
    --set-val LRNG_RCT_CUTOFF 31 \
    --set-val LRNG_APT_CUTOFF 325 \
    -e LRNG_IRQ \
    -e LRNG_CONTINUOUS_COMPRESSION_ENABLED \
    -d LRNG_CONTINUOUS_COMPRESSION_DISABLED \
    -e LRNG_ENABLE_CONTINUOUS_COMPRESSION \
    -e LRNG_SWITCHABLE_CONTINUOUS_COMPRESSION \
    --set-val LRNG_IRQ_ENTROPY_RATE 256 \
    -e LRNG_JENT \
    --set-val LRNG_JENT_ENTROPY_RATE 16 \
    -e LRNG_CPU \
    --set-val LRNG_CPU_FULL_ENT_MULTIPLIER 1 \
    --set-val LRNG_CPU_ENTROPY_RATE 8 \
    -e LRNG_SCHED \
    --set-val LRNG_SCHED_ENTROPY_RATE 4294967295 \
    -e LRNG_DRNG_CHACHA20 \
    -m LRNG_DRBG \
    -m LRNG_DRNG_KCAPI \
    -e LRNG_SWITCH \
    -e LRNG_SWITCH_HASH \
    -m LRNG_HASH_KCAPI \
    -e LRNG_SWITCH_DRNG \
    -m LRNG_SWITCH_DRBG \
    -m LRNG_SWITCH_DRNG_KCAPI \
    -e LRNG_DFLT_DRNG_CHACHA20 \
    -d LRNG_DFLT_DRNG_DRBG \
    -d LRNG_DFLT_DRNG_KCAPI \
    -e LRNG_TESTING_MENU \
    -d LRNG_RAW_HIRES_ENTROPY \
    -d LRNG_RAW_JIFFIES_ENTROPY \
    -d LRNG_RAW_IRQ_ENTROPY \
    -d LRNG_RAW_RETIP_ENTROPY \
    -d LRNG_RAW_REGS_ENTROPY \
    -d LRNG_RAW_ARRAY \
    -d LRNG_IRQ_PERF \
    -d LRNG_RAW_SCHED_HIRES_ENTROPY \
    -d LRNG_RAW_SCHED_PID_ENTROPY \
    -d LRNG_RAW_SCHED_START_TIME_ENTROPY \
    -d LRNG_RAW_SCHED_NVCSW_ENTROPY \
    -d LRNG_SCHED_PERF \
    -d LRNG_ACVT_HASH \
    -d LRNG_RUNTIME_MAX_WO_RESEED_CONFIG \
    -d LRNG_TEST_CPU_ES_COMPRESSION \
    -e LRNG_SELFTEST \
    -d LRNG_SELFTEST_PANIC \
    -d LRNG_RUNTIME_FORCE_SEEDING_DISABLE

### BPF
scripts/config \
    -d BPF_LSM \
    -d BPF_PRELOAD \
    -d BPF_STREAM_PARSER \
    -d BPF_KPROBE_OVERRIDE \
    -d BPF_LIRC_MODE2 \
    -d LWTUNNEL_BPF \
    -d HID_BPF

### Debug
scripts/config \
    -d DEBUG_INFO_BTF \
    -d DEBUG_INFO_DWARF4 \
    -d DEBUG_INFO_DWARF5 \
    -d PAHOLE_HAS_SPLIT_BTF \
    -d DEBUG_INFO_BTF_MODULES \
    -d SLUB_DEBUG \
    -d PM_DEBUG \
    -d PM_ADVANCED_DEBUG \
    -d PM_SLEEP_DEBUG \
    -d ACPI_DEBUG \
    -d SCHED_DEBUG \
    -d LATENCYTOP \
    -d DEBUG_PREEMPT

### Framebuffer
scripts/config \
    -e SYSFB_SIMPLEFB

### Cleanup
scripts/config \
    -d ACPI_PRMT \
    -d HYPERVISOR_GUEST \
    -d RTW88

### Arch-SKM
if [ -d /usr/src/certs-local ]; then
    scripts/config \
        -e MODULE_SIG_FORCE \
        -d MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS
fi
