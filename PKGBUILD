
_major=5.19
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

source=("$_kernel/v5.x/$_src.tar.xz"
        "$_kernel/v5.x/$_src.tar.sign"
        "$_master/releases/download/$_zen/$_zen.patch.xz"
        "$_master/releases/download/$_zen/$_zen.patch.xz.sig"
        "https://github.com/archlinux/svntogit-packages/raw/master/linux-zen/trunk/config"
        '0001-x86-tools-fix-llvm-objdump-syntax.patch' # https://github.com/ClangBuiltLinux/linux/issues/1362
        '0002-ideapad-laptop-add-platform-support-for-Ideapad-3-15ADA05-81W1.patch'
        '0003-tsc-directsync-gross-hack.patch' # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        '0101-ZEN-c8baa9403457cbb209fcd27ffacde75276f13c3e.patch'::"$_master/commit/c8baa9403457cbb209fcd27ffacde75276f13c3e.patch"
        '0102-ZEN-0c5d9f33d1d80e5d6f37179c601f7cb1b6f6b730.patch'::"$_master/commit/0c5d9f33d1d80e5d6f37179c601f7cb1b6f6b730.patch"
        '0103-ZEN-3d2321ece857fcf56f510f828412bdb7b06246f0.patch'::"$_master/commit/3d2321ece857fcf56f510f828412bdb7b06246f0.patch"
        '0104-ZEN-7b60a634dc58cbf262ff95cde972af224b04bbfb.patch'::"$_master/commit/7b60a634dc58cbf262ff95cde972af224b04bbfb.patch"
        '0105-ZEN-e5f7e4b4c920f9c4d27da5d6f852dd2b62fa7b0e.patch'::"$_master/commit/e5f7e4b4c920f9c4d27da5d6f852dd2b62fa7b0e.patch"
        '0106-ZEN-169cc6e56d6a1ace370a3d40f6588ab4c0a96348.patch'::"$_master/commit/169cc6e56d6a1ace370a3d40f6588ab4c0a96348.patch"
        '0107-ZEN-9a9552214eb040fbbb9185e6dc248cef5813aa9e.patch'::"$_master/commit/9a9552214eb040fbbb9185e6dc248cef5813aa9e.patch"
        '0108-ZEN-5e8acc4cb0dc63e86c86717398519a6f0b1b3bcd.patch'::"$_master/commit/5e8acc4cb0dc63e86c86717398519a6f0b1b3bcd.patch"
        '0109-ZEN-9d7f022688c409598c909543894697ae28af6aa3.patch'::"$_master/commit/9d7f022688c409598c909543894697ae28af6aa3.patch"
        '0110-XANMOD-Change-rcutree.kthread_prio-to-SCHED_RR-polic.patch'::"https://github.com/xanmod/linux/commit/de786c7df0de3439513aece65b9a1fde6cecad19.patch"
        '0111-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch'::"$_xanmod/xanmod/0003-XANMOD-block-mq-deadline-Disable-front_merges-by-def.patch"
        '0112-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch'::"$_xanmod/xanmod/0004-XANMOD-block-mq-deadline-Increase-write-priority-to-.patch"
        '0113-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0005-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0124-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0006-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0125-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0012-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0126-XANMOD-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch'::"$_xanmod/net/mac80221/0001-mac80211-ignore-AP-power-level-when-tx-power-type-is.patch"
        '0127-LUCJAN-zstd-dev-patches.patch'::"$_lucjan/zstd-dev-patches/0001-zstd-dev-patches.patch")

sha256sums=('ff240c579b9ee1affc318917de07394fc1c3bb49dac25ec1287370c2e15005a8'
            'SKIP'
            'c69d33f2a9666014a11f6f3db067d927e8b6e0d05276a5ff51abdf399b585c7c'
            'SKIP'
            '4b6ac8f746749dddb9bdcff5c555d543e268900d3a0f270df91af158617dec30'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'ee03df755ae52b04c40c979e9e04745f9c0c8ce34bcc5a3c652bf3029268ad27'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            '623b4dfac1bcb8910b6a011c4971418ffb0e067aec0010a7b1d8540b0b52282e'
            '0371e14f09385da05b097cf560e98c5fa04ced1bb3ec2ec99378baf292f0223f'
            'c785941852f9a96f60d78fd0aed96f1154e2a6130c4f6b7336caf2d9069a80e4'
            '7a5ee40ac5bc18e5efb95336deb99312ffee0a85ee26a27400341195cf1e3bbf'
            '1ed479aaae3d2e1df32458186df519f8e8f64c851e3ae1dcf77f2df01b726e15'
            'bf614aef93523a5828ee683fbacd7c921496426d6e080d83fc2307442e3e82d4'
            'a29d28a9e04aabcfef7f4442934a4dba8de597315376fb41ca247b39bb42a925'
            '3919a32cbf309b67608ea6aa87e2bb1455cdbd8043050e6bc606831f46a118ff'
            'c50e8d2a8503f0fc864875b9145286394a801a22d42ab9b1ece00d657d2f72a4'
            '118f84db306c610c2db22af547f0a7d95001c4378c0172807b1d294f39e3df07'
            '0b8eb02d9ae6c4e118ce96f57f54d08374370ba5d94c7250a0e80475b3d0d023'
            '5f5b13c0cb5e61a846397726e6996ae9aebe007f877fee6c037d49ff0a957acd'
            '19fa5af7e7fad5a9f2435e3b75a877b72dc5f21964818738e859e3ac87511597'
            '014c395c8f05f5ef5274afc70d75fd3e2ac941e1389eac7f33580f8cd3643842'
            'd71d691a17ba0c6a92187951b39272cf862d24cddec680e05c6b79ffe7df6356'
            '95cf8cdb90a177bc9087cf38aafaa27d077104731dc07c7ae22b954766721602'
            '5f99a44ad4239827ad687a473bd7e5b0a345b28c90eddc84b9f71031a5f6a583')

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
