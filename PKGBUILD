
_major=6.1
_minor=6.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=2.1

_src="linux-$_major"
_zen="v${pkgver%.*}-${pkgver##*.}"

_kernel="https://cdn.kernel.org/pub/linux/kernel"
_source="https://github.com/zen-kernel/zen-kernel"
_xanmod="https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod"
_lucjan="https://raw.githubusercontent.com/sirlucjan/kernel-patches/master/$_major"

arch=('x86_64')
url="$_source/commits/$_zen"
license=('GPL2')

makedepends=('bc' 'clang' 'cpio' 'git' 'kmod' 'libelf' 'llvm' 'lld' 'pahole' 'perl' 'tar' 'xmlto' 'xz')
options=('!strip')

source=("$_kernel/v6.x/$_src.tar.xz"
        "$_kernel/v6.x/$_src.tar.sign"
        "$_source/releases/download/$_zen/$_zen.patch.xz"
        "$_source/releases/download/$_zen/$_zen.patch.xz.sig"
        'https://github.com/archlinux/svntogit-packages/raw/master/linux-zen/trunk/config'
        '0001-x86-tools-fix-llvm-objdump-syntax.patch' # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-add-platform-support-for-Ideapad-3-15ADA05-81W1.patch'
        '0003-tsc-directsync.patch' # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0101-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_lucjan/xanmod-patches-sep/0001-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0102-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch'::"$_lucjan/xanmod-patches-sep/0002-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0103-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_lucjan/xanmod-patches-sep/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0104-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_lucjan/xanmod-patches-sep/0009-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0105-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"$_xanmod/net/mac80221/0001-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch"
        '0106-LUCJAN-winesync-Introduce-the-winesync-driver-and-character.patch'::"$_lucjan/wine-sync-patches/0001-winesync-Introduce-the-winesync-driver-and-character.patch"
        '0107-LUCJAN-futex-6.1-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch'::"$_lucjan/futex-patches-v4/0001-futex-6.1-Add-entry-point-for-FUTEX_WAIT_MULTIPLE-op.patch"
        '0108-LUCJAN-ext4-6.1-merge-changes-from-dev-tree.patch'::"$_lucjan/ext4-patches-v4/0001-ext4-6.1-merge-changes-from-dev-tree.patch"
        '0109-LUCJAN-zstd-6.1-merge-changes-from-dev-tree.patch'::"$_lucjan/zstd-cachyos-patches-v2/0001-zstd-6.1-merge-changes-from-dev-tree.patch"
        '0110-LUCJAN-x86-Avoid-relocation-information-in-final-vmlinux.patch'::"$_lucjan/vmlinuz-cachyos-patches/0001-x86-Avoid-relocation-information-in-final-vmlinux.patch"
        '0111-d9f543e131bdfdd8ea07724d77eed6a22e42bbc2.patch'::"$_source/commit/d9f543e131bdfdd8ea07724d77eed6a22e42bbc2.patch"
        '0112-4296f3193d1b4374c09640504bf30e02ba02753d.patch'::"$_source/commit/4296f3193d1b4374c09640504bf30e02ba02753d.patch"
        '0113-6ed91ba7f1d460920a16447a1d0f0a596be61b0c.patch'::"$_source/commit/6ed91ba7f1d460920a16447a1d0f0a596be61b0c.patch")

sha256sums=('2ca1f17051a430f6fed1196e4952717507171acfd97d96577212502703b25deb'
            'SKIP'
            'fa17707cf50c0502fa197491b3d4c0fab2b570dca5dd650da2b5ce6f72888c94'
            'SKIP'
            '2ca6409bce85bd68cfd1bcffb9e4bf2da9be3abe656e4127dff90631a4a46d40'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            '44277bfdd594c01798b493fe59fabb03a12aa751e2f9bc47e2fa5fd129f7a5d2'
            'a45bb3fbbf39739f08e8ce2388346ce8e27e22d0db6c22138bb8b81b93220026'
            '818832d2249586f576572f79d6e4273ab011a177a6402df4adf34e495487d3bb'
            'd626143b97d9fd897a42f1954fd752473ed45e34946be50cc63436a8cd355dac'
            'e29825f0884d58afa9b29a2bca9c473e3f54683077c481a07869843864076b2f'
            '7d1cb23b12b52a94692048526f076e20cedb8fed9f9b8a40a4e2995341d01c33'
            '980385eb7b6eb998e794992cd414ee8972a02364d9a970449d19d3a037f13a24'
            '658a592a47bbae03737d4e0060520db2ed05876258780118125510e290282cdf'
            '30c7bc5d02b72cef2cc8a6a7bf047ee85419aea836450abac38fe44b3c4ef021'
            '624fa85265dfa9a39f8ce4007037bbb5cdd80a2c96b998cb95eb13700075285b'
            '0238102ee19941f8a3a811eaa95c0495ac458bf0383615ce62bcc97f4ec48079'
            '5e6bdf4ff3650c1b35ecdde9cb8041f41023cd315e48410ff0f4c6a5acd5ce45'
            '7be264cae4eaaeffb50ab473dd952ad70bc46a4b9e0e9f315d95cd9ee8fd007e'
            '5cc6cbb3f7aaa745d02f7a5fb03327f0620753b92e6c47f31768ab2a6ef9cac7'
            '3d292831740a2bef4f205ccb452ede0407e6b8f91e02bbe16b0b2a04bf04e2c5')

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
    scripts/config -d PSI

    # Device drivers
    scripts/config -e CONFIG_FW_LOADER_COMPRESS_XZ
    scripts/config -e SYSFB_SIMPLEFB

    # Processor type and features
    scripts/config --set-val NR_CPUS 16
    scripts/config -e MZEN -d GENERIC_CPU
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
    scripts/config -d RTW88

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
    $_makecmd -j$(nproc) all
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
