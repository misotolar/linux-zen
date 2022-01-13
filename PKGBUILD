_major=5.16
_minor=zen1

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
        '0101-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0102-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0004-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0103-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0104-LUCJAN-x86-csum-rewrite-csum_partial.patch'::"$_lucjan/fixes-miscellaneous-sep/0010-x86-csum-rewrite-csum_partial.patch"
        '0105-LUCJAN-x86-csum-Fix-compilation-error-for-UM.patch'::"$_lucjan/fixes-miscellaneous-sep/0011-x86-csum-Fix-compilation-error-for-UM.patch"
        '0106-LUCJAN-x86-csum-Fix-initial-seed-for-odd-buffers.patch'::"$_lucjan/fixes-miscellaneous-sep/0012-x86-csum-Fix-initial-seed-for-odd-buffers.patch"
        '0107-LUCJAN-net-patches.patch'::"$_lucjan/net-patches-v3/0001-net-patches.patch"
        '0108-LUCJAN-PRJC.patch'::"$_lucjan/prjc-patches-v2/0001-PRJC-for-$_major.patch"
        '0109-LUCJAN-sched-alt-Add-MG-LRU-changes-through-ifdef-macro.patch'::"$_lucjan/prjc-lru-patches-v2/0001-sched-alt-Add-MG-LRU-changes-through-ifdef-macro.patch"
        '0110-LUCJAN-prjc-fixes.patch'::"$_lucjan/prjc-fixes/0001-prjc-fixes.patch"
        '0111-LUCJAN-UKSM.patch'::"$_lucjan/uksm-patches/0001-UKSM-for-$_major.patch")

sha256sums=('027d7e8988bb69ac12ee92406c3be1fe13f990b1ca2249e226225cd1573308bb'
            'SKIP'
            '92507ec370db1c940e496f877c3ee279a05ffca954bef8def241a1ce65269d91'
            'SKIP'
            'f8d332e96d1d5826b386a87e1588fef9c94c36638228718eb847658efa07dbaa'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'ee03df755ae52b04c40c979e9e04745f9c0c8ce34bcc5a3c652bf3029268ad27'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            'c6b37e668e85cec65bdf1a81e4b40659b6a7e545d25842eb7a1d3322fbdf68e7'
            '4e0cca8b30d5495f43bf656c2f4872fd13b5396c2912dee1cc2774ee4a04272d'
            'd5cd8860689edd358fe4330bf584a2b8a647c068c082db847403d98866c24bfe'
            'c6a73b5593f3ed36f06819ab4aa663ae0edd37b00a4a28522c5201dbcba9d29e'
            '128332855defc27092f919d8f220dd62555ff838d741420ba2d330e24ba9be93'
            '0524d0591b2f376df24e44b6e0e25acb3a4db4088530ff103c1b24f7f79fd0b1'
            'db0d2fde8f1e994fbb4eb37c8affa3f0b339aa658f9ab5003bb2ce453a68ab95'
            '65d385e78b66068bce83ac9bf136b21d2428a5f4de1d2c4c0adb4bfed6b8573b'
            'b4b8f68b1393a3387f73ac7adeff33343fb4c52fbd1f946835d4e57983e21913'
            'ff34181ee7a52ce740f63f5613ec99cfaccbeec5fe55e57a034d6d9938e5f2aa'
            'dc3a5d24305da05124c004b191d071d5b00c6a89e435acfc7bbd9034732775bc')

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
