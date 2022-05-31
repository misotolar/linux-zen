_major=5.18
_minor=1.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=2

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
        '0101-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0005-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0102-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0006-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0103-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0012-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0104-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"$_lucjan/xanmod-patches-sep/0004-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch"
        '0105-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch'::"$_lucjan/xanmod-patches-sep/0005-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch"
        '0106-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_lucjan/xanmod-patches-sep/0006-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0107-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch'::"$_lucjan/xanmod-patches-sep/0007-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0108-LUCJAN-PRJC-for-5.18.patch'::"$_lucjan/prjc-patches-v6/0001-PRJC-for-5.18.patch"
        '0109-LUCJAN-prjc-fixes.patch'::"$_lucjan/prjc-fixes-v3/0001-prjc-fixes.patch"
        '0110-LUCJAN-zstd-dev-patches.patch'::"$_lucjan/zstd-dev-patches/0001-zstd-dev-patches.patch")

sha256sums=('51f3f1684a896e797182a0907299cc1f0ff5e5b51dd9a55478ae63a409855cee'
            'SKIP'
            '92a7d0463cb0c568d94b2c1a0fb57bd39456b16d9eec1c6d7ff376819745acde'
            'SKIP'
            '5770ad7cc2d34367193cfbeb2a8a37e46c73470b3f6ec7ad63a1cadab4245fbc'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'ee03df755ae52b04c40c979e9e04745f9c0c8ce34bcc5a3c652bf3029268ad27'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            '04777c1b39fe16a156a5058f06772d34d64b29702702f99c3aa72243a54aea16'
            '0115e8938f26127ea05343406bc89d0d09a361f737e55b0765771564cd5e2aae'
            '98b7324a240e43b0459f25575c94780cea0dff9c1fc5109fae408008641d940c'
            'ee230cf6a8799f70ed136ca43829dfa392589253195a2f05504043b641b05c67'
            '9e7d8596ea55292ed7458d0bb891321eba9bd6c064abacff269cca97d5937dc5'
            '7a76668f0e7e5bb742aa8c807f5d5c5361aed3400f65df38f22ffbbf240ed802'
            '13ae96cfeb799750fc1200ac8e414c70163881b2d95d9db859d7ad100e59a9cf'
            'c6c332c3cd44bdbb82923cdeb6b8c6bfc539ed42e439b11d82093d575c79bbc0'
            '431c196158f9a852fd382c79befbe6b45e3fca44f8612ff0e03f6cdb0867637b'
            'adfa5c97033023dfa85bf5f0d71110cce90c55f0c5fb12c0b5c6eb1d64ac0875')

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

    # add resolve_btfids
    install -Dt "$builddir"/tools/bpf/resolve_btfids tools/bpf/resolve_btfids/resolve_btfids

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
