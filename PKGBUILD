_major=5.17
_minor=1.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=1

_src="linux-$_major"
_zen="v${pkgver%.*}-${pkgver##*.}"

_xanmod="https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod"
_lucjan="https://raw.githubusercontent.com/sirlucjan/kernel-patches/master/$_major"

arch=('x86_64')
url="https://github.com/zen-kernel/zen-kernel/commits/$_zen"
license=('GPL2')

makedepends=('bc' 'clang' 'cpio' 'git' 'kmod' 'libelf' 'llvm' 'lld' 'pahole' 'perl' 'rsync' 'tar' 'xmlto' 'xz' 'zstd')
options=('!strip')

source=("https://cdn.kernel.org/pub/linux/kernel/v5.x/$_src.tar.xz"
        "https://cdn.kernel.org/pub/linux/kernel/v5.x/$_src.tar.sign"
        "https://github.com/zen-kernel/zen-kernel/releases/download/$_zen/$_zen.patch.xz"
        "https://github.com/zen-kernel/zen-kernel/releases/download/$_zen/$_zen.patch.xz.sig"
        "https://raw.githubusercontent.com/archlinux/svntogit-packages/packages/linux-zen/trunk/config"
        '0001-x86-tools-fix-llvm-objdump-syntax.patch'  # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-add-platform-support-for-Ideapad-3-15ADA05-81W1.patch'
        '0003-tsc-directsync-gross-hack.patch'          # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0101-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_xanmod/xanmod/0002-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0102-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0103-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0004-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0104-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0105-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch'::"$_lucjan/xanmod-patches-v3-sep/0005-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch"
        '0106-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"$_lucjan/xanmod-patches-v3-sep/0004-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch"
        '0107-LUCJAN-PRJC-for-5.17.patch'::"$_lucjan/prjc-patches/0001-PRJC-for-5.17.patch"
        '0108-LUCJAN-sched-alt-Add-MG-LRU-changes-through-ifdef-macro.patch'::"$_lucjan/prjc-lru-patches/0001-sched-alt-Add-MG-LRU-changes-through-ifdef-macro.patch"
        '0109-LUCJAN-prjc-fixes.patch'::"$_lucjan/prjc-fixes-v2/0001-prjc-fixes.patch"
        '0110-LUCJAN-zstd-dev-patches.patch'::"$_lucjan/zstd-dev-patches/0001-zstd-dev-patches.patch")

sha256sums=('555fef61dddb591a83d62dd04e252792f9af4ba9ef14683f64840e46fa20b1b1'
            'SKIP'
            'df62cc46c41212860fe1e9058e69f7022e5cbbe6588b418801162e365adaf6db'
            'SKIP'
            '812250d12684c263c2db878d0d49539cb4f987790d74d42225ae3f51f3e28133'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'ee03df755ae52b04c40c979e9e04745f9c0c8ce34bcc5a3c652bf3029268ad27'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            'c98db26c0861eeb99aed205f4b097486793e385934f0ce9d726724edf649fac5'
            'b06c7eec6114c05196613048a308b598c8873def7bfdabbea3d4a983f62c19cb'
            '0f3fc59eb50305c82b93ad56c640695399eb38453345b7ed1e10886223f5cb47'
            'c949b420494e2c020eb5a59bf067aa4aeaf35980da6500b1be18cd77973de166'
            '0462e8ef0b57c660256e720dc8303dbb72ee276391ffaabcc4ef709ccb060fcd'
            'c0f08a845a4ee94b87242d90a018e23b906d0d5ee575cf1b57128f82af3b9b29'
            '6f1fbed65deab3ec19b186a2d59ae94297b366719d2302d1b72bf7c7bcc85179'
            'fd8682f349e573e5a7674766b41ee0ed97aebb74e2c806b747ebc3a1662c31ed'
            'da8f9fca99da74cbd213fdcf04aa636cb9bbb815b7c19d1a82905d6c468c93fd'
            '3c866fd701c89167febc0ea3d97f332183c157a18df4b2a07d4ad78ed258f0c2')

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
        ./genkeys.sh

        msg2 "Updating kernel config with new key..."
        ./fix_config.sh ../src/config

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
    scripts/config -e LTO_CLANG_THIN -d LTO_NONE

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
    optdepends=('crda: to set the correct wireless channels of your country'
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
        key_dir=$(<${certs_local_src}/current_key_dir)

        certs_local_dst="${builddir}/certs-local"
        signer="sign_manual.sh"
        mkdir -p ${certs_local_dst}
        rsync -a $certs_local_src/{current,$key_dir,$signer} $certs_local_dst/

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
