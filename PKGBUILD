_major=5.17
_minor=6.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=3

_src="linux-$_major"
_zen="v${pkgver%.*}-${pkgver##*.}"

_kernel="https://cdn.kernel.org/pub/linux/kernel"
_master="https://github.com/zen-kernel/zen-kernel"
_xanmod="https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod"
_lucjan="https://raw.githubusercontent.com/sirlucjan/kernel-patches/master/$_major"

arch=('x86_64')
url="$_master/commits/$_zen"
license=('GPL2')

makedepends=('bc' 'clang' 'cpio' 'git' 'kmod' 'libelf' 'llvm' 'lld' 'pahole' 'perl' 'tar' 'xmlto' 'xz')
options=('!strip')

source=("$_kernel/v5.x/$_src.tar.xz"
        "$_kernel/v5.x/$_src.tar.sign"
        "$_master/releases/download/$_zen/$_zen.patch.xz"
        "$_master/releases/download/$_zen/$_zen.patch.xz.sig"
        "https://github.com/archlinux/svntogit-packages/raw/master/linux-zen/trunk/config"
        '0001-x86-tools-fix-llvm-objdump-syntax.patch' # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-add-platform-support-for-Ideapad-3-15ADA05-81W1.patch'
        '0003-tsc-directsync-gross-hack.patch' # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0101-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0102-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0004-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0103-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0104-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"$_lucjan/xanmod-patches-v4-sep/0004-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch"
        '0105-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch'::"$_lucjan/xanmod-patches-v4-sep/0005-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch"
        '0106-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_lucjan/xanmod-patches-v4-sep/0006-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0107-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch'::"$_lucjan/xanmod-patches-v4-sep/0007-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0108-LUCJAN-alt_core.c-Add-potentially-missing-idle-on_rq-assign.patch'::"$_lucjan/prjc-fixes-v7-sep/0004-alt_core.c-Add-potentially-missing-idle-on_rq-assign.patch"
        '0109-LUCJAN-sched-alt-Sync-32ed980c3020-sched-Remove-unused-inli.patch'::"$_lucjan/prjc-fixes-v7-sep/0006-sched-alt-Sync-32ed980c3020-sched-Remove-unused-inli.patch"
        '0110-LUCJAN-sched-alt-Sync-sched-sugov-Ignore-busy-filter-when-r.patch'::"$_lucjan/prjc-fixes-v7-sep/0007-sched-alt-Sync-sched-sugov-Ignore-busy-filter-when-r.patch"
        '0111-LUCJAN-sched-alt-Sync-sched-uclamp-Fix-iowait-boost-escapin.patch'::"$_lucjan/prjc-fixes-v7-sep/0008-sched-alt-Sync-sched-uclamp-Fix-iowait-boost-escapin.patch"
        '0112-LUCJAN-zstd-dev-patches.patch'::"$_lucjan/zstd-dev-patches-v8/0001-zstd-dev-patches.patch")

sha256sums=('555fef61dddb591a83d62dd04e252792f9af4ba9ef14683f64840e46fa20b1b1'
            'SKIP'
            'f7ae6633bea9e13480314a74685f443ae5662b433b14d33b5ff1eeb42d436080'
            'SKIP'
            'ea604f8457e97764d604b3e484f372ab7b30452ef112acb23b399d39c954faaf'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'ee03df755ae52b04c40c979e9e04745f9c0c8ce34bcc5a3c652bf3029268ad27'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            'b06c7eec6114c05196613048a308b598c8873def7bfdabbea3d4a983f62c19cb'
            '0f3fc59eb50305c82b93ad56c640695399eb38453345b7ed1e10886223f5cb47'
            'c949b420494e2c020eb5a59bf067aa4aeaf35980da6500b1be18cd77973de166'
            'fa5bdb2550f745a5fc518015fa8cf4dcec04183b5ec75ec19c76c062ec9d79d6'
            '29d6ff69d6108eb68fcd43a01578a5c570007bd49e15299b8e86d38c945b66d5'
            'b1e3fc5c46c92b273cacfc230abad3ea452e4d188dec96e29138280470ba489f'
            'c394be99f2c6824754b00e26bef2eecec67de1f171c4dc32ebd5fe97fae95031'
            'fa036f3c3156e0d88c4c7ec187c9f21725f536a17df6cc2325f652bcddfcdaeb'
            '21ce18c0567b055bb96f9b64aa2d6ba6c7f9e9dac304f5b190394452ffaec86e'
            'a0781a49d6d26dc0a5cc5b857520f1293fbb66ef22f461025d7a8060d35d9d43'
            '652541d5132b736a10fe6334a4884f3258a340ebe5e1479729efeccd9f092452'
            '90f8c2c3c5f0434dfbd6d35b8858e4075ef852697f3839479f2c31075cd4d993')

validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886'   # Linus Torvalds
              '647F28654894E3BD457199BE38DBBDC86092693E'   # Greg Kroah-Hartman
              'A2FF3A36AAA56654109064AB19802F8B0D70FC30'   # Jan Alexander Steffens (heftig)
              'C5ADB4F3FEBBCE27A3E54D7D9AE4078033F8024D')  # Steven Barrett <steven@liquorix.net>

export KBUILD_BUILD_HOST="$(hostname 2>/dev/null || echo -n archlinux)"
export KBUILD_BUILD_USER=$pkgbase
export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

_makecmd="make LLVM=1 LLVM_IAS=1"

prepare() {
    
    if [ -d /usr/src/certs-local ]; then
        msg2 "Rebuilding local signing key..."
        cp -rf /usr/src/certs-local ../
        cd ../certs-local

        msg2 "Updating kernel config with new key..."
        ./genkeys.py -v --config ../src/config

        cd ../src
    fi

    cd $_src

    echo "Setting version..."
    scripts/setlocalversion --save-scmversion
    echo "-$pkgrel" > localversion.10-pkgrel
    echo "${pkgbase#linux}" > localversion.20-pkgname
    if [[ "archlinux" != "$KBUILD_BUILD_HOST" ]]; then
        echo "-$KBUILD_BUILD_HOST" > localversion.20-pkgname
    fi

    echo "Applying patch $_zen.patch..."
    patch -Nsp1 < "../$_zen.patch"

    local src
    for src in "${source[@]}"; do
        src="${src%%::*}"
        src="${src##*/}"
        [[ $src = *.patch ]] || continue
        echo "Applying patch $src..."
        patch -Nsp1 < "../$src"
    done

    echo "Setting config..."
    cp ../config .config

    $_makecmd olddefconfig
    if [ -f "$HOME/.config/modprobed.db" ]; then
        yes "" | $_makecmd LSMOD=$HOME/.config/modprobed.db localmodconfig >/dev/null
    fi

    # General setup
    scripts/config --set-str DEFAULT_HOSTNAME "$KBUILD_BUILD_HOST"
    scripts/config --set-val RCU_BOOST_DELAY 331
    scripts/config -e SCHED_ALT -e SCHED_PDS
    scripts/config -d SCHED_BMQ
    scripts/config -d BPF_LSM
    scripts/config -d BPF_PRELOAD
    scripts/config -d MQ_IOSCHED_KYBER
    scripts/config -e PSI_DEFAULT_DISABLED

    # Device drivers
    scripts/config -e CONFIG_FW_LOADER_COMPRESS_XZ
    scripts/config -e SYSFB_SIMPLEFB

    # Processor type and features
    scripts/config --set-val NR_CPUS 16
    scripts/config -e MZEN -d GENERIC_CPU
    scripts/config -e HZ_500 -d HZ_1000
    scripts/config -d HYPERVISOR_GUEST
    scripts/config -d MICROCODE_INTEL
    scripts/config -d MICROCODE_OLD_INTERFACE
    scripts/config -d NUMA

    # Power management and ACPI options
    scripts/config -d ACPI_PRMT

    # General architecture-dependent options
    scripts/config -e LTO_CLANG_FULL -d LTO_NONE

    # Enable loadable module support
    if [ -d /usr/src/certs-local ]; then
        scripts/config -e MODULE_SIG_FORCE
        scripts/config -d MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS
    fi

    # Networking support
    scripts/config -d TCP_CONG_CUBIC -d DEFAULT_CUBIC
    scripts/config -e TCP_CONG_BBR2 -e DEFAULT_BBR2

    # Device Drivers
    scripts/config -e RANDOM_TRUST_CPU
    scripts/config -d BPF_LIRC_MODE2
    scripts/config -d INTEL_IOMMU
    scripts/config -d WATCHDOG
    scripts/config -d ANDROID
    scripts/config -d ASHMEM 

    # Security options
    scripts/config -d SECURITY_SELINUX
    scripts/config -d SECURITY_TOMOYO
    scripts/config -d SECURITY_YAMA

    # Kernel hacking
    scripts/config -d DEBUG_INFO
    scripts/config -d SYMBOLIC_ERRNAME
    scripts/config -d BPF_KPROBE_OVERRIDE
    scripts/config -d FTRACE

    $_makecmd -s kernelrelease > version
    echo "Prepared $pkgbase version $(<version)"
}

build() {
    cd $_src
    $_makecmd -j$(nproc) all
}

_package() {
    pkgdesc="The $pkgdesc kernel and modules"
    depends=('coreutils' 'kmod' 'initramfs')
    optdepends=('wireless-regdb: to set the correct wireless channels of your country'
                'linux-firmware: firmware images needed for some devices')
    provides=(VIRTUALBOX-GUEST-MODULES WIREGUARD-MODULE VHBA-MODULE KSMBD-MODULE)
    replaces=()

    cd $_src
    local kernver="$(<version)"
    local modulesdir="$pkgdir/usr/lib/modules/$kernver"

    echo "Installing boot image..."
    # systemd expects to find the kernel here to allow hibernation
    # https://github.com/systemd/systemd/commit/edda44605f06a41fb86b7ab8128dcf99161d2344
    install -Dm644 "$($_makecmd -s image_name)" "$modulesdir/vmlinuz"

    # Used by mkinitcpio to name the kernel
    echo "$pkgbase" | install -Dm644 /dev/stdin "$modulesdir/pkgbase"

    echo "Installing modules..."
    $_makecmd INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 modules_install

    # remove build and source links
    rm "$modulesdir"/{source,build}
}

_package-headers() {
    pkgdesc="Headers and scripts for building modules for the $pkgdesc kernel"
    depends=('pahole')

    cd $_src
    local builddir="$pkgdir/usr/lib/modules/$(<version)/build"

    echo "Installing build files..."
    install -Dt "$builddir" -m644 .config Makefile Module.symvers System.map localversion.* version vmlinux
    install -Dt "$builddir/kernel" -m644 kernel/Makefile
    install -Dt "$builddir/arch/x86" -m644 arch/x86/Makefile
    cp -t "$builddir" -a scripts

    # required when STACK_VALIDATION is enabled
    install -Dt "$builddir/tools/objtool" tools/objtool/objtool

    # required when DEBUG_INFO_BTF_MODULES is enabled
    mkdir -p "$builddir"/{fs/xfs,mm}

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
    case "$(file -bi "$file")" in
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
