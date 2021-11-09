_major=5.15
_minor=1.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=2

_src="linux-$_major"
_zen="v${pkgver%.*}-${pkgver##*.}"

arch=('x86_64')
url="https://github.com/zen-kernel/zen-kernel/commits/$_zen"
license=('GPL2')

makedepends=('arch-sign-modules' 'bc' 'clang' 'cpio' 'git' 'kmod' 'libelf' 'llvm' 'lld' 'pahole' 'perl' 'rsync' 'tar' 'xmlto' 'xz' 'zstd')
options=('!strip')

source=("https://cdn.kernel.org/pub/linux/kernel/v5.x/$_src.tar.xz"
        "https://cdn.kernel.org/pub/linux/kernel/v5.x/$_src.tar.sign"
        "https://github.com/zen-kernel/zen-kernel/releases/download/$_zen/$_zen.patch.xz"
        "https://github.com/zen-kernel/zen-kernel/releases/download/$_zen/$_zen.patch.xz.sig"
        "https://raw.githubusercontent.com/archlinux/svntogit-packages/packages/linux-zen/trunk/config"
        '0001-x86-tools-fix-llvm-objdump-syntax.patch'  # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-remove-dytc-version-check.patch'
        '0003-tsc-directsync-gross-hack.patch'          # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0004-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/xanmod/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0005-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/xanmod/0004-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0006-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/xanmod/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0007-XANMOD-lib-zstd-Add-kernel-specific-API.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0001-lib-zstd-Add-kernel-specific-API.patch"
        '0008-XANMOD-lib-zstd-Add-decompress_sources.h-for-decompress_unz.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0002-lib-zstd-Add-decompress_sources.h-for-decompress_unz.patch"
        '0009-XANMOD-lib-zstd-Upgrade-to-latest-upstream-zstd-version-1.4.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0003-lib-zstd-Upgrade-to-latest-upstream-zstd-version-1.4.patch"
        '0010-XANMOD-MAINTAINERS-Add-maintainer-entry-for-zstd.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0004-MAINTAINERS-Add-maintainer-entry-for-zstd.patch"
        '0011-XANMOD-kbuild-Add-make-tarzst-pkg-build-option.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0005-kbuild-Add-make-tarzst-pkg-build-option.patch"
        '0012-XANMOD-lib-zstd-Add-cast-to-silence-clang-s-Wbitwise-instea.patch'::"https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod/lib_zstd/0006-lib-zstd-Add-cast-to-silence-clang-s-Wbitwise-instea.patch")

sha256sums=('57b2cf6991910e3b67a1b3490022e8a0674b6965c74c12da1e99d138d1991ee8'
            'SKIP'
            '9c57af26c74164e2a274b0cd6649cbcdfdb247b8087395908ab4213ac4a5ab2b'
            'SKIP'
            'a79850315d88c15af88a1f71978e2d3b8e86a706e0d744dd837fb08a09f6ac6c'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'cee6ac8807cec8cc47dc383e90aee651dd544bd778cb458eb249a0d79fe44467'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            '254f3408b87b57a0ba7efaeb5e1e1168dbbcaee3c8563be0676db2e932908013'
            '9cbd6dc9e98354127bf976125717a7366607d296bfe4ada4f3b0b30f4289c6ed'
            '0921a18963631ed8de7b61bf0d3099efe1c54474f7c69f482a83e7aaa9f4db7f'
            '58da9db644a0a5d6b8e05a3c0a29eb08be4749b456964d5ea8bc3ee38b0b3092'
            '3b71745b6623ba47ece7f391502191c06cb8cd94943448496c76c68bb638bbc3'
            'c7e7faa24936c927446f204bf2756efbd6107d44e6fc72284ad02261a106c6d9'
            'd4965df8129092e25483f9508fb7e5fc5161c16845c61bbebea1363c3df8b33a'
            '01fc1e457e652b8283aec1fbdf3f5f895be2cddf1c969a9a01cacbb14fda1cef'
            '1395d66cc9af1974fea34a4bb53a43d9e8b2a49b3c2610edf220eff5e92c90e7')

validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886'   # Linus Torvalds
              '647F28654894E3BD457199BE38DBBDC86092693E'   # Greg Kroah-Hartman
              'A2FF3A36AAA56654109064AB19802F8B0D70FC30'   # Jan Alexander Steffens (heftig)
              'C5ADB4F3FEBBCE27A3E54D7D9AE4078033F8024D')  # Steven Barrett <steven@liquorix.net>

export KBUILD_BUILD_HOST=`hostname`
export KBUILD_BUILD_USER=$pkgbase
export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

_makecmd="make LLVM=1 LLVM_IAS=1"

prepare() {
    msg2 "Rebuilding local signing key..."
    cp -rf /usr/src/certs-local ../
    cd ../certs-local
    ./genkeys.sh

    msg2 "Updating kernel config with new key..."
    ./fix_config.sh ../src/config

    cd ../src/$_src

    echo "Setting version..."
    scripts/setlocalversion --save-scmversion
    echo "-$pkgrel" > localversion.10-pkgrel
    echo "-$KBUILD_BUILD_HOST" > localversion.20-pkgname

    echo "Appling patch $_zen.patch..."
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
    scripts/config -e MODULE_SIG_FORCE
    scripts/config -d MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS

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

    # add objtool for external module building and enabled VALIDATION_STACK option
    install -Dt "$builddir/tools/objtool" tools/objtool/objtool

    # add xfs and shmem for aufs building
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
}

for _p in "${pkgname[@]}"; do
    eval "package_$_p() {
        $(declare -f "_package${_p#$pkgbase}")
        _package${_p#$pkgbase}
    }"
done
