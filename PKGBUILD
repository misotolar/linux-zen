_major=5.15
_minor=5.zen1

pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver="$_major.$_minor"
pkgrel=1

_src="linux-$_major"
_zen="v${pkgver%.*}-${pkgver##*.}"

_xanmod="https://raw.githubusercontent.com/xanmod/linux-patches/master/linux-$_major.y-xanmod"

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
        '0004-scsi-sd-fix-sd_do_mode_sense-buffer-length-handling.patch'
        '0101-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch'::"$_xanmod/xanmod/0003-XANMOD-block-set-rq_affinity-to-force-full-multithre.patch"
        '0102-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch'::"$_xanmod/xanmod/0004-XANMOD-kconfig-add-500Hz-timer-interrupt-kernel-conf.patch"
        '0103-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch'::"$_xanmod/xanmod/0010-XANMOD-lib-kconfig.debug-disable-default-CONFIG_SYMB.patch"
        '0104-XANMOD-lib-zstd-Add-kernel-specific-API.patch'::"$_xanmod/lib_zstd/0001-lib-zstd-Add-kernel-specific-API.patch"
        '0105-XANMOD-lib-zstd-Add-decompress_sources.h-for-decompress_unz.patch'::"$_xanmod/lib_zstd/0002-lib-zstd-Add-decompress_sources.h-for-decompress_unz.patch"
        '0106-XANMOD-lib-zstd-Upgrade-to-latest-upstream-zstd-version-1.4.patch'::"$_xanmod/lib_zstd/0003-lib-zstd-Upgrade-to-latest-upstream-zstd-version-1.4.patch"
        '0107-XANMOD-MAINTAINERS-Add-maintainer-entry-for-zstd.patch'::"$_xanmod/lib_zstd/0004-MAINTAINERS-Add-maintainer-entry-for-zstd.patch"
        '0108-XANMOD-kbuild-Add-make-tarzst-pkg-build-option.patch'::"$_xanmod/lib_zstd/0005-kbuild-Add-make-tarzst-pkg-build-option.patch"
        '0109-XANMOD-lib-zstd-Add-cast-to-silence-clang-s-Wbitwise-instea.patch'::"$_xanmod/lib_zstd/0006-lib-zstd-Add-cast-to-silence-clang-s-Wbitwise-instea.patch"
        '0110-XANMOD-net-introduce-sk_forward_alloc_get.patch'::"$_xanmod/net/0001-net-introduce-sk_forward_alloc_get.patch"
        '0111-XANMOD-tcp-move-inet-rx_dst_ifindex-to-sk-sk_rx_dst_ifindex.patch'::"$_xanmod/net/0002-tcp-move-inet-rx_dst_ifindex-to-sk-sk_rx_dst_ifindex.patch"
        '0112-XANMOD-ipv6-move-inet6_sk-sk-rx_dst_cookie-to-sk-sk_rx_dst_.patch'::"$_xanmod/net/0003-ipv6-move-inet6_sk-sk-rx_dst_cookie-to-sk-sk_rx_dst_.patch"
        '0113-XANMOD-bpf-sockmap-Use-stricter-sk-state-checks-in-sk_looku.patch'::"$_xanmod/net/0004-bpf-sockmap-Use-stricter-sk-state-checks-in-sk_looku.patch"
        '0114-XANMOD-tcp-minor-optimization-in-tcp_add_backlog.patch'::"$_xanmod/net/0005-tcp-minor-optimization-in-tcp_add_backlog.patch"
        '0115-XANMOD-tcp-remove-dead-code-in-__tcp_v6_send_check.patch'::"$_xanmod/net/0006-tcp-remove-dead-code-in-__tcp_v6_send_check.patch"
        '0116-XANMOD-tcp-small-optimization-in-tcp_v6_send_check.patch'::"$_xanmod/net/0007-tcp-small-optimization-in-tcp_v6_send_check.patch"
        '0117-XANMOD-net-use-sk_is_tcp-in-more-places.patch'::"$_xanmod/net/0008-net-use-sk_is_tcp-in-more-places.patch"
        '0118-XANMOD-net-remove-sk_route_forced_caps.patch'::"$_xanmod/net/0009-net-remove-sk_route_forced_caps.patch"
        '0119-XANMOD-net-remove-sk_route_nocaps.patch'::"$_xanmod/net/0010-net-remove-sk_route_nocaps.patch"
        '0120-XANMOD-ipv6-shrink-struct-ipcm6_cookie.patch'::"$_xanmod/net/0011-ipv6-shrink-struct-ipcm6_cookie.patch"
        '0121-XANMOD-net-shrink-struct-sock-by-8-bytes.patch'::"$_xanmod/net/0012-net-shrink-struct-sock-by-8-bytes.patch"
        '0122-XANMOD-net-forward_alloc_get-depends-on-CONFIG_MPTCP.patch'::"$_xanmod/net/0013-net-forward_alloc_get-depends-on-CONFIG_MPTCP.patch"
        '0123-XANMOD-net-cache-align-tcp_memory_allocated-tcp_sockets_all.patch'::"$_xanmod/net/0014-net-cache-align-tcp_memory_allocated-tcp_sockets_all.patch"
        '0124-XANMOD-tcp-small-optimization-in-tcp-recvmsg.patch'::"$_xanmod/net/0015-tcp-small-optimization-in-tcp-recvmsg.patch"
        '0125-XANMOD-tcp-add-RETPOLINE-mitigation-to-sk_backlog_rcv.patch'::"$_xanmod/net/0016-tcp-add-RETPOLINE-mitigation-to-sk_backlog_rcv.patch"
        '0126-XANMOD-tcp-annotate-data-races-on-tp-segs_in-and-tp-data_se.patch'::"$_xanmod/net/0017-tcp-annotate-data-races-on-tp-segs_in-and-tp-data_se.patch"
        '0127-XANMOD-tcp-annotate-races-around-tp-urg_data.patch'::"$_xanmod/net/0018-tcp-annotate-races-around-tp-urg_data.patch"
        '0128-XANMOD-tcp-tp-urg_data-is-unlikely-to-be-set.patch'::"$_xanmod/net/0019-tcp-tp-urg_data-is-unlikely-to-be-set.patch"
        '0129-XANMOD-tcp-avoid-indirect-calls-to-sock_rfree.patch'::"$_xanmod/net/0020-tcp-avoid-indirect-calls-to-sock_rfree.patch"
        '0130-XANMOD-tcp-defer-skb-freeing-after-socket-lock-is-released.patch'::"$_xanmod/net/0021-tcp-defer-skb-freeing-after-socket-lock-is-released.patch"
        '0131-XANMOD-tcp-check-local-var-timeo-before-socket-fields-in-on.patch'::"$_xanmod/net/0022-tcp-check-local-var-timeo-before-socket-fields-in-on.patch"
        '0132-XANMOD-tcp-do-not-call-tcp_cleanup_rbuf-if-we-have-a-backlo.patch'::"$_xanmod/net/0023-tcp-do-not-call-tcp_cleanup_rbuf-if-we-have-a-backlo.patch"
        '0133-XANMOD-net-move-early-demux-fields-close-to-sk_refcnt.patch'::"$_xanmod/net/0024-net-move-early-demux-fields-close-to-sk_refcnt.patch")

sha256sums=('57b2cf6991910e3b67a1b3490022e8a0674b6965c74c12da1e99d138d1991ee8'
            'SKIP'
            '7cb7b33a3e990ab1dbbf9284587cd50fe4546de7e4f4618708cefa92128ffcac'
            'SKIP'
            'a8eaf6eb21cca77aa470443c8a0d07577023edee3d589c4de6e7d0f66eebbc99'
            'd5ce94a811ef49161fb681dff5e48ae52e4dafbbf17270613fbbd1a3f87e3fee'
            'cee6ac8807cec8cc47dc383e90aee651dd544bd778cb458eb249a0d79fe44467'
            '4d2ad28ed803d7b382f9e0ba6f449c1a0d8d0d8f1ecc31fde56f4556cefc802e'
            '3b006d2b859f00ef21c85b07d08d5ab5a0360dc75e7348f6856d9679d055fc79'
            '254f3408b87b57a0ba7efaeb5e1e1168dbbcaee3c8563be0676db2e932908013'
            '9cbd6dc9e98354127bf976125717a7366607d296bfe4ada4f3b0b30f4289c6ed'
            '0921a18963631ed8de7b61bf0d3099efe1c54474f7c69f482a83e7aaa9f4db7f'
            '58da9db644a0a5d6b8e05a3c0a29eb08be4749b456964d5ea8bc3ee38b0b3092'
            '3b71745b6623ba47ece7f391502191c06cb8cd94943448496c76c68bb638bbc3'
            'c7e7faa24936c927446f204bf2756efbd6107d44e6fc72284ad02261a106c6d9'
            'd4965df8129092e25483f9508fb7e5fc5161c16845c61bbebea1363c3df8b33a'
            '01fc1e457e652b8283aec1fbdf3f5f895be2cddf1c969a9a01cacbb14fda1cef'
            '1395d66cc9af1974fea34a4bb53a43d9e8b2a49b3c2610edf220eff5e92c90e7'
            'b49b8104460ffe81b3a2cc6d7a64c2c2a099e9f36700eff79c246b1a087f0c75'
            '37dcd2e6f19ac9b51b93879239e437fdb1f041e3e3819efa762dd8bf46900ef6'
            '965757313f9b31b6213bf50e0b9d09a303441a8ad85c4a3a7813906348c778d5'
            '28b1ded74d65d52eabf5a6fbb0c244b3d9429c170254c68eece44afaa9f1dbff'
            'a55d3bb8045ebcceceaecad903d01dcefa9877478e7c3be40293d976bf21b262'
            'e0dccf09799dd84148ade06412c218c6a42861f58719fb6a5778f5e88016e00d'
            '4c2a38a05f50351fee44d41cedf677737346642c7b991b24967d86c6e3c0c523'
            'd7598f8fa9938a7078107f8391ef5f3d1b2100083790bb510a2d0ddf2dd4e95b'
            'a81a47506cc3a985daee9ffddf8ef49adf2b22e3359b2452c1f453a891bc83ed'
            'f5ada528853f58fcfbbf94f66657f352d44bbb7bc1d452450d693b28f89e9b06'
            'e2d6fe0f0665916c718abbe38c99429a4e858b86a40dda94b354cee8d103c888'
            'd5aedf1b52c0117874b9b4225fdd0396fbfd39c389d3bba4e7befcbab48dd33c'
            '1ed06975eddc5e4e44752b3b1cf57a172b4cf7f15af5eb13dee56922e669799a'
            '0df20f174cc149f198cc1ff86b79772074e1b5fcc99ee3cd2d442dda1675f3d0'
            'ef493717ecae9a0fb9e06755278be52a2424ea79a4d0a4dd30e7657fe0e3b0af'
            '584aa9fede6dc91a6cae7415027c0960434e070d1e69e73eb9ed7dc97c0711ce'
            '9ef87dc8173fed19d517c8ecfb91f16e0ceae8f71846d9457adf88c4d41852ca'
            'fe2ec23c73e24058d3a0826dd73cefd22f82d781807e7365a5c951e73306b144'
            '8b4067dd2041c6d4ae80dc382e77040e3487ccd663be30fb99e9aa7219f981b1'
            'd4526ffdc23451fdfe4cd95a31b4936bbceb1aabafb0681e0a2d7f8ee5c7ccc9'
            'a201fa0a714db4f1d7d89fa93275a7b119c9e338f35862b84a1947e1fae4f556'
            '806913a4b270f53630efe416f574f658051f3a900d23c6d624f590a4d410d213'
            '9f4998eea0058da76fe2fabc792405f29597e63499cee3d47463b6c41cb40f42'
            '0f88485cdeec5a9a99be91a6e7e1deef96d3f81f9ffd6205e1e136ec4a72a575')

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
