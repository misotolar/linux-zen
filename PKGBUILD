
_major=6.3
_minor=1.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='The Linux ZEN kernel and modules'
pkgver="$_major.$_minor"
pkgrel=1

_srcdir="linux-$_major"
_zenver="v${pkgver%.*}-${pkgver##*.}"

_kernel="https://cdn.kernel.org/pub/linux/kernel"
_source="https://github.com/zen-kernel/zen-kernel"

_lucjan="https://raw.githubusercontent.com/sirlucjan/kernel-patches/master/$_major"
_tkg="https://raw.githubusercontent.com/Frogging-Family/linux-tkg/master/linux-tkg-patches/$_major"

arch=('x86_64' 'x86_64_v3')
url="$_source/commits/$_zenver"
license=('GPL2')

makedepends=('bc' 'clang' 'cpio' 'gettext' 'git' 'kmod' 'libelf' 'llvm' 'lld' 'pahole' 'perl' 'python' 'tar' 'xz')
options=('!strip')

source=("$_kernel/v6.x/linux-$_major.tar.xz"
        "$_kernel/v6.x/linux-$_major.tar.sign"
        "$_source/releases/download/$_zenver/$_zenver.patch.xz"
        "$_source/releases/download/$_zenver/$_zenver.patch.xz.sig"
        'https://github.com/archlinux/svntogit-packages/raw/master/linux-zen/trunk/config'
        'https://raw.githubusercontent.com/CachyOS/linux-cachyos/master/linux-cachyos/auto-cpu-optimization.sh'
        '0001-kconfig-additional-timer-interrupt-kernel-config-opt.patch'
        '0002-x86-implement-tsc-directsync-for-systems-without-IA3.patch'
        '0003-x86-touch-clocksource-watchdog-after-syncing-TSCs.patch'
        '0004-x86-save-restore-TSC-counter-value-during-sleep-wake.patch'
        '0005-x86-only-restore-TSC-if-we-have-IA32_TSC_ADJUST-or-d.patch'
        '0006-x86-don-t-check-for-random-warps-if-using-direct-syn.patch'
        '0007-x86-disable-tsc-watchdog-if-using-direct-sync.patch'
        '0008-x86-Avoid-relocation-information-in-final-vmlinux.patch'
        '0009-Revert-ZEN-Add-graysky-s-more-uarches.patch'
        '0101-LUCJAN-cpu-cachyos-patches.patch'::"$_lucjan/cpu-cachyos-patches-v2/0001-cpu-cachyos-patches.patch"
        '0102-LUCJAN-block-mq-deadline-Increase-write-priority-to-.patch'::"$_lucjan/xanmod-patches-v2-sep/0003-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0103-LUCJAN-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_lucjan/xanmod-patches-v2-sep/0004-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0104-LUCJAN-block-set-rq_affinity-to-force-full-multithre.patch'::"$_lucjan/xanmod-patches-v2-sep/0005-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0105-LUCJAN-lrng-6.3-introduce-Linux-Random-Number-Generator.patch'::"$_lucjan/lrng-cachyos-patches/0001-lrng-6.3-introduce-Linux-Random-Number-Generator.patch"
        '0106-LUCJAN-futex-6.3-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch'::"$_lucjan/futex-patches/0001-futex-6.3-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch"
        '0107-LUCJAN-ext4-6.3-merge-changes-from-dev-tree.patch'::"$_lucjan/ext4-patches-v2/0001-ext4-6.3-merge-changes-from-dev-tree.patch"
        '0108-LUCJAN-zstd-6.3-merge-changes-from-dev-tree.patch'::"$_lucjan/zstd-cachyos-patches/0001-zstd-6.3-merge-changes-from-dev-tree.patch"
        '0109-LUCJAN-clang-6.3-add-miscellaneous-fixes-for-clang.patch'::"$_lucjan/clang-patches/0001-clang-6.3-add-miscellaneous-fixes-for-clang.patch")

sha256sums=('ba3491f5ed6bd270a370c440434e3d69085fcdd528922fa01e73d7657db73b1e'
            'SKIP'
            '0bf539219acafa4eed7fc3c92035f1e2f95e7e7faf239374c06ae05981792ef3'
            'SKIP'
            '0bc9e02b66d43c0c9f32206504377d6e60c010747215a776b47daf97dac99483'
            '41c34759ed248175e905c57a25e2b0ed09b11d054fe1a8783d37459f34984106'
            'a99a0101fb71e748124cd1021f40766ba4d234110d52f9ca3585b0c6e36daf29'
            '54f77dca3802a9e1036d20cacbc3356823f038b63b6792225a51cc4b8630fa34'
            'd65bd6c210896610b54abfad15b86756382d3a1eb48835b6a2e16ea5ea541863'
            '70472f2ffc33a40796abe7eca9ba5c534fe2b6c035bad1dd13cb6bcd7acd58ab'
            'f544db22d1ddd9dd482ba552309775671ffb3c712cd43a9fae6fc0152868cc94'
            'd7e2500fe861c78e3087431f2964f4e79eb2cd3588aadff746f9a9e9b5913804'
            '3f51da3f1ed5a0d115e69047ef9fd1cfb36adf48d0e6d812fbf449b61db5d373'
            'e8dd037119d4468d066fd73ce10e107d47a628977333bbecf149597cab912690'
            'b501582a2c5402fa5d6a3a84962d0b6d807f3a13b2338ddbaff008e2bc1e1b0e'
            '4ecc858dd647f82255504c7e86f5a40690a1964fca7ee150b361a67890c8f180'
            'af73e70396b9752b476bab0762d0a3c78369d78f522284bbd05cce6dae77ee74'
            '8a3eef02f44c7c887d23a61275cd55542b8aa6802021f71e8d0b1d753c501559'
            '562fe86f9aca31bae96384d73c439830ce4be3f2f19f06689dd532a7cadc2a96'
            '4fe53e7db394ad31e21e91f5bc8014b6b0c9fcbbf85b04addc627fd05fab042a'
            'c744c7977c1d651fd83e88ef74d0fdec6c20af1fe6aaf7cfecc78d414ac7bc1c'
            '20c1150970fcc802d920184e9d073a3043a4143abccd36c8f53636a5e338bbca'
            '19a04d22d291bbc4c2fc3263e943eaa8f2f29c5d85825f3d584bd948350895f6'
            '4b96f1148e161ff19f4e84894cffb66943ba4bddb62d35710b83e2215e1fc25e')

validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886'   # Linus Torvalds
              '647F28654894E3BD457199BE38DBBDC86092693E'   # Greg Kroah-Hartman
              'A2FF3A36AAA56654109064AB19802F8B0D70FC30'   # Jan Alexander Steffens (heftig)
              'C5ADB4F3FEBBCE27A3E54D7D9AE4078033F8024D')  # Steven Barrett <steven@liquorix.net>

export KBUILD_BUILD_HOST="$(hostname 2>/dev/null || echo -n archlinux)"
export KBUILD_BUILD_USER=$pkgbase
export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

_make() {
  test -s version
  make CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 KERNELRELEASE="$(<version)" "$@"
}

prepare() {

    ### Arch-SKM
    if [ -d /usr/src/certs-local ]; then
        msg2 "Rebuilding local signing key..."
        cp -rf /usr/src/certs-local ../
        cd ../certs-local

        msg2 "Updating kernel config with new key..."
        ./genkeys.py -v --config ../src/config

        cd ../src
    fi

    cd $_srcdir
    echo "Applying patch $_zenver.patch..."
    patch -Nsp1 < "../$_zenver.patch"

    local src
    for src in "${source[@]}"; do
        src="${src%%::*}"
        src="${src##*/}"
        [[ $src = *.patch ]] || continue
        echo "Applying patch $src..."
        patch -Nsp1 < "../$src"
    done

    echo "Setting version..."
    echo "-$pkgrel" > localversion.10-pkgrel
    echo "${pkgbase#linux}" > localversion.20-pkgname
    if [[ "archlinux" != "$KBUILD_BUILD_HOST" ]]; then
        echo "-$KBUILD_BUILD_HOST" > localversion.20-pkgname
    fi

    make defconfig >/dev/null
    make -s kernelrelease > version
    make mrproper >/dev/null

    echo "Setting config..."
    cp ../config .config

    _make olddefconfig
    if [ -f "$HOME/.config/modprobed.db" ]; then
        yes "" | _make LSMOD=$HOME/.config/modprobed.db localmodconfig >/dev/null
    fi

    ### Hostname
    scripts/config --set-str DEFAULT_HOSTNAME "$KBUILD_BUILD_HOST"

    ### RCU priority
    scripts/config --set-val RCU_BOOST_DELAY 331

    ### CPU optimization
    if [[ "archlinux" != "$KBUILD_BUILD_HOST" ]]; then
        sh "${srcdir}"/auto-cpu-optimization.sh >/dev/null
    fi

    ### CPU scheduler
    scripts/config -e SCHED_ALT \
        -e SCHED_PDS \
        -d SCHED_BMQ

    ### LLVM level
    scripts/config -e LTO \
        -e LTO_CLANG \
        -e ARCH_SUPPORTS_LTO_CLANG \
        -e ARCH_SUPPORTS_LTO_CLANG_THIN \
        -d LTO_NONE \
        -e HAS_LTO_CLANG \
        -e HAVE_GCC_PLUGINS \
        -e "LTO_CLANG_${_LTO_CLANG:-THIN}"

    ### Tick rate
    scripts/config -d HZ_1000 \
        -e "HZ_${_HZ:-1000}" \
        --set-val HZ ${_HZ:-1000}

    ### PSI
    scripts/config -d PSI

    ### NUMA
    scripts/config -d NUMA \
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
        scripts/config --set-val NR_CPUS $(($(nproc)*2))
    fi

    ### I/O schedulers
    scripts/config -d MQ_IOSCHED_KYBER

    ### Performance governor
    scripts/config -d CPU_FREQ_DEFAULT_GOV_SCHEDUTIL \
        -e CPU_FREQ_DEFAULT_GOV_PERFORMANCE

    ### TCP congestion control
    scripts/config -d DEFAULT_CUBIC \
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
    scripts/config -d RANDOM_DEFAULT_IMPL \
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

    ### Debug
    scripts/config -d SLUB_DEBUG \
        -d PM_DEBUG \
        -d PM_ADVANCED_DEBUG \
        -d PM_SLEEP_DEBUG \
        -d ACPI_DEBUG \
        -d SCHED_DEBUG \
        -d LATENCYTOP \
        -d DEBUG_PREEMPT

    ### Framebuffer
    scripts/config -e SYSFB_SIMPLEFB

    ### Cleanup
    scripts/config -d ACPI_PRMT
    scripts/config -d HYPERVISOR_GUEST
    scripts/config -d RTW88

    ### Arch-SKM
    if [ -d /usr/src/certs-local ]; then
        scripts/config -e MODULE_SIG_FORCE
        scripts/config -d MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS
    fi

    echo "Prepared $pkgbase version $(<version)"
}

build() {
    cd $_srcdir
    _make -j$(nproc) all
}

_package() {
    pkgdesc="The $pkgdesc kernel and modules"
    depends=('coreutils' 'kmod' 'initramfs')
    optdepends=('wireless-regdb: to set the correct wireless channels of your country'
                'uksmd: userspace KSM helper daemon'
                'linux-firmware: firmware images needed for some devices')
    provides=(KSMBD-MODULE VHBA-MODULE UKSMD-BUILTIN VIRTUALBOX-GUEST-MODULES WIREGUARD-MODULE)
    replaces=()

    cd $_srcdir
    local modulesdir="$pkgdir/usr/lib/modules/$(<version)"

    echo "Installing boot image..."
    # systemd expects to find the kernel here to allow hibernation
    # https://github.com/systemd/systemd/commit/edda44605f06a41fb86b7ab8128dcf99161d2344
    install -Dm644 "$(_make -s image_name)" "$modulesdir/vmlinuz"

    # Used by mkinitcpio to name the kernel
    echo "$pkgbase" | install -Dm644 /dev/stdin "$modulesdir/pkgbase"

    echo "Installing modules..."
    _make INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 modules_install

    # remove build and source links
    rm "$modulesdir"/{source,build}
}

_package-headers() {
    pkgdesc="Headers and scripts for building modules for the $pkgdesc kernel"
    depends=('pahole')

    cd $_srcdir
    local builddir="$pkgdir/usr/lib/modules/$(<version)/build"

    echo "Installing build files..."
    install -Dt "$builddir" -m644 .config Makefile Module.symvers System.map localversion.* version vmlinux
    install -Dt "$builddir/kernel" -m644 kernel/Makefile
    install -Dt "$builddir/arch/x86" -m644 arch/x86/Makefile
    cp -t "$builddir" -a scripts

    # required when STACK_VALIDATION is enabled
    install -Dt "$builddir/tools/objtool" tools/objtool/objtool

    # required when DEBUG_INFO_BTF_MODULES is enabled
    if [ -f tools/bpf/resolve_btfids/resolve_btfids ]; then
        install -Dt "$builddir/tools/bpf/resolve_btfids" tools/bpf/resolve_btfids/resolve_btfids
    fi

    echo "Installing headers..."
    cp -t "$builddir" -a include
    cp -t "$builddir/arch/x86" -a arch/x86/include
    install -Dt "$builddir/arch/x86/kernel" -m644 arch/x86/kernel/asm-offsets.s

    install -Dt "$builddir/drivers/md" -m644 drivers/md/*.h
    install -Dt "$builddir/net/mac80211" -m644 net/mac80211/*.h

    # https://bugs.archlinux.org/task/13146
    install -Dt "$builddir/drivers/media/i2c" -m644 drivers/media/i2c/msp3400-driver.h

    # https://bugs.archlinux.org/task/20402
    install -Dt "$builddir/drivers/media/usb/dvb-usb" -m644 drivers/media/usb/dvb-usb/*.h
    install -Dt "$builddir/drivers/media/dvb-frontends" -m644 drivers/media/dvb-frontends/*.h
    install -Dt "$builddir/drivers/media/tuners" -m644 drivers/media/tuners/*.h

    # https://bugs.archlinux.org/task/71392
    install -Dt "$builddir/drivers/iio/common/hid-sensors" -m644 drivers/iio/common/hid-sensors/*.h

    echo "Installing KConfig files..."
    find . -name 'Kconfig*' -exec install -Dm644 {} "$builddir/{}" \;

    echo "Removing unneeded architectures..."
    local arch
    for arch in "$builddir"/arch/*/; do
        [[ $arch = */x86/ ]] && continue
        echo "Removing $(basename "$arch")"
        rm -r "$arch"
    done

    echo "Removing documentation..."
    rm -r "$builddir/Documentation"

    echo "Removing broken symlinks..."
    find -L "$builddir" -type l -printf 'Removing %P\n' -delete

    echo "Removing loose objects..."
    find "$builddir" -type f -name '*.o' -printf 'Removing %P\n' -delete

    echo "Stripping build tools..."
    local file
    while read -rd '' file; do
    case "$(file -Sib "$file")" in
        application/x-sharedlib\;*)      # Libraries (.so)
            strip -v $STRIP_SHARED "$file" ;;
        application/x-archive\;*)        # Libraries (.a)
            strip -v $STRIP_STATIC "$file" ;;
        application/x-executable\;*)     # Binaries
            strip -v $STRIP_BINARIES "$file" ;;
        application/x-pie-executable\;*) # Relocatable binaries
            strip -v $STRIP_SHARED "$file" ;;
    esac
    done < <(find "$builddir" -type f -perm -u+x ! -name vmlinux -print0)

    echo "Stripping vmlinux..."
    strip -v $STRIP_STATIC "$builddir/vmlinux"

    echo "Adding symlink..."
    mkdir -p "$pkgdir/usr/src"
    ln -sr "$builddir" "$pkgdir/usr/src/$pkgbase"

    if [ -d /usr/src/certs-local ]; then
        msg2 "Local signing certs for out-of-tree modules..."

        certs_local_src="../../certs-local"
        certs_local_dst="${builddir}/certs-local"

        # Certificates
        ${certs_local_src}/install-certs.py $certs_local_dst

        # DKMS tools
        dkms_src="$certs_local_src/dkms"
        dkms_dst="${pkgdir}/etc/dkms"
        mkdir -p $dkms_dst

        rsync -a $dkms_src/{kernel-sign.conf,kernel-sign.sh} $dkms_dst/
    fi
}

for _p in "${pkgname[@]}"; do
    eval "package_$_p() {
        $(declare -f "_package${_p#$pkgbase}")
        _package${_p#$pkgbase}
    }"
done
