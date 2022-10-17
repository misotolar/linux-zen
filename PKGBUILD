
_major=6.0
_minor=2.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=1

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

source=("$_kernel/v6.x/$_src.tar.xz"
        "$_kernel/v6.x/$_src.tar.sign"
        "$_master/releases/download/$_zen/$_zen.patch.xz"
        "$_master/releases/download/$_zen/$_zen.patch.xz.sig"
        "https://github.com/archlinux/svntogit-packages/raw/master/linux-zen/trunk/config"
        '0001-x86-tools-fix-llvm-objdump-syntax.patch' # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-add-platform-support-for-Ideapad-3-15ADA05-81W1.patch'
        '0003-tsc-directsync-gross-hack.patch' # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0101-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch'::"$_lucjan/xanmod-patches-v3-sep/0001-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch"
        '0102-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_lucjan/xanmod-patches-v3-sep/0002-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0103-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch'::"$_lucjan/xanmod-patches-v3-sep/0003-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0104-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_lucjan/xanmod-patches-v3-sep/0004-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0105-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_lucjan/xanmod-patches-v3-sep/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0106-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"https://github.com/xanmod/linux/commit/babc130da078cc40e9478a6952b1cc9930ade00b.patch"
        '0107-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"https://github.com/xanmod/linux/commit/c6d0bc235374d5581af4bb56b40f20496a42a651.patch"
        '0108-LUCJAN-futex-6.0-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch'::"$_lucjan/futex-cachyos-patches/0001-futex-6.0-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch"
        '0109-LUCJAN-x86-Avoid-relocation-information-in-final-vmlinux.patch'::"$_lucjan/vmlinuz-cachyos-patches/0001-x86-Avoid-relocation-information-in-final-vmlinux.patch"
        '0110-LUCJAN-zstd-6.0-merge-changes-from-dev-tree.patch'::"$_lucjan/zstd-dev-patches/0001-zstd-6.0-merge-changes-from-dev-tree.patch"
        '0111-LUCJAN-PRJC-CachyOS-for-6.0.patch'::"$_lucjan/prjc-cachyos-patches-v3/0001-PRJC-CachyOS-for-6.0.patch")

sha256sums=('5c2443a5538de52688efb55c27ab0539c1f5eb58c0cfd16a2b9fbb08fd81788e'
            'SKIP'
            '2aaea956bf366fdeb1200ef6204a911a493bd0f40dd70f441e7beaa6660abc26'
            'SKIP'
            '4415388555aab8845e60f6b3996e3a75b8159d516b7b04a6adb8ade54de3ff9c'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            '44277bfdd594c01798b493fe59fabb03a12aa751e2f9bc47e2fa5fd129f7a5d2'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            '4a485c1ddfdaec5f552dd9dd775316a0077c2f49f4c630d86bb60350e4a0e180'
            '0e7cb6478ab0898bc42d479cfc47ad3d696a22f2385d2a03453bc476060862dd'
            '2074deb0316923a83e39410d4321fec4cd2a74f4b90a9c5458be718f763d4705'
            '772a79491a77a43c91f8a2b43b57e36826919598c6b93716810fff9b9e07707a'
            'ccd48b2d439bd0ca09f9cea2beb4d4bec1e996e4c48115c8a21f6580ecd75742'
            '79db8c5187b3bf422795f48899dd1170a56360506e81c6af4d840eb283429c47'
            'f3eb844f7f0cc85d541491ca3bcb51c3e24d16a91c2a0ba589618eeed86ba822'
            '14757a57364cd693c645c469da3d86b380705587ba71ef8bfda842cf49a4527c'
            'cb4861772c99c6d5a7816b062ff061a05f01dec4a5de66b9c5ebb1434747e474'
            '534aadd267865f30411b3b5058965c2e44419d4a6d46934cb48bebb833004fd1'
            'b1f356db00877c164b253e2f25e5260d50052ffcdd7e962efc9b5017cdfcae8e')

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
    scripts/config -e "LTO_CLANG_${_LTO_CLANG:-THIN}" -d LTO_NONE

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
    scripts/config -d DEBUG_INFO_BTF
    scripts/config -d SYMBOLIC_ERRNAME
    scripts/config -d BPF_KPROBE_OVERRIDE
    scripts/config -d FTRACE

    $_makecmd -s kernelrelease > version
    echo "Prepared $pkgbase version $(<version)"
}

build() {
    cd $_src
    $_makecmd -j $(($(nproc)+1)) all
}

_package() {
    pkgdesc="The $pkgdesc kernel and modules"
    depends=('coreutils' 'kmod' 'initramfs')
    optdepends=('wireless-regdb: to set the correct wireless channels of your country'
                'uksmd: userspace KSM helper daemon'
                'linux-firmware: firmware images needed for some devices')
    provides=(KSMBD-MODULE VHBA-MODULE UKSMD-BUILTIN VIRTUALBOX-GUEST-MODULES WIREGUARD-MODULE)
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
