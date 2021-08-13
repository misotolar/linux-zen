pkgbase=linux-zen
pkgname=("$pkgbase" "$pkgbase-headers")
pkgdesc='Linux ZEN'
pkgver=5.13.10.zen1
pkgrel=1

_srctag=v${pkgver%.*}-${pkgver##*.}
_srcname=zen-kernel

arch=('x86_64')
url="https://github.com/zen-kernel/zen-kernel/commits/$_srctag"
license=('GPL2')

makedepends=('arch-sign-modules' 'bc' 'cpio' 'git' 'kmod' 'libelf' 'pahole' 'perl' 'rsync' 'tar' 'xmlto' 'zstd')
options=('!strip')

source=("$_srcname::git+https://github.com/zen-kernel/zen-kernel?signed#tag=$_srctag"
        '0001-tsc-directsync.patch' # https://bugzilla.kernel.org/show_bug.cgi?id=202525
        'config')

sha256sums=('SKIP'
            '7cb07c4c10d1bcce25d1073dbb9892faa0ccff10b4b61bb4f2f0d53e3e8a3958'
            'cca6a2f213c6b90f1db435a4985458d1faf2309d26ed880c9c33fdd66e089f0c')

validpgpkeys=('ABAF11C65A2970B130ABE3C479BE3E4300411886'   # Linus Torvalds
              '647F28654894E3BD457199BE38DBBDC86092693E'   # Greg Kroah-Hartman
              'A2FF3A36AAA56654109064AB19802F8B0D70FC30'   # Jan Alexander Steffens (heftig)
              'C5ADB4F3FEBBCE27A3E54D7D9AE4078033F8024D')  # Steven Barrett <steven@liquorix.net>

export KBUILD_BUILD_HOST=`hostname`
export KBUILD_BUILD_USER=$pkgbase
export KBUILD_BUILD_TIMESTAMP="$(date -Ru${SOURCE_DATE_EPOCH:+d @$SOURCE_DATE_EPOCH})"

prepare() {
    msg2 "Rebuilding local signing key..."
    cp -rf /usr/src/certs-local ../

    sed -i 's/#O = Unspecified company/O = Michal Sotolar/' ../certs-local/x509.oot.genkey
    sed -i 's/CN = Local Out of tree kernel module signing key/CN = Local kernel module signing key/' ../certs-local/x509.oot.genkey
    sed -i 's/#emailAddress = unspecified.user@unspecified.company/emailAddress = michal@sotolar.com/' ../certs-local/x509.oot.genkey 

    cd ../certs-local
    ./genkeys.sh

    msg2 "Updating kernel config with new key..."

    ./fix_config.sh ../src/config

    cd ../src/$_srcname

    echo "Setting version..."
    scripts/setlocalversion --save-scmversion
    echo "-$pkgrel" > localversion.10-pkgrel
    echo "-$KBUILD_BUILD_HOST" > localversion.20-pkgname

    local src
    for src in "${source[@]}"; do
        src="${src%%::*}"
        src="${src##*/}"
        [[ $src = *.patch ]] || continue
        echo "Applying patch $src..."
        patch -Np1 < "../$src"
    done

    echo "Setting config..."
    cp ../config .config

    sed -i 's/CONFIG_GENERIC_CPU=y/# CONFIG_GENERIC_CPU is not set/' .config
    sed -i 's/# CONFIG_MZEN1 is not set/CONFIG_MZEN1=y/' .config

    sed -i 's/CONFIG_HZ_1000=y/# CONFIG_HZ_1000 is not set/' .config
    sed -i 's/# CONFIG_HZ_300 is not set/CONFIG_HZ_300=y/' .config
    sed -i 's/CONFIG_HZ=1000/CONFIG_HZ=300/' .config

    # General setup
    scripts/config --set-str DEFAULT_HOSTNAME "$KBUILD_BUILD_HOST"

    # Processor type and features
    scripts/config -d HYPERVISOR_GUEST
    scripts/config -d GART_IOMMU
    scripts/config -d INTEL_IOMMU
    scripts/config -d MICROCODE_INTEL
    scripts/config -d MICROCODE_OLD_INTERFACE
    scripts/config -d NUMA

    # Enable loadable module support
    scripts/config -e MODULE_SIG_FORCE
    scripts/config -d MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS

    # Device Drivers
    scripts/config -e RANDOM_TRUST_CPU
    scripts/config -d WATCHDOG

    # Security options
    scripts/config -d SECURITY_SELINUX
    scripts/config -d SECURITY_TOMOYO
    scripts/config -d SECURITY_YAMA

    # Kernel hacking
    scripts/config -d CONFIG_DEBUG_INFO
    scripts/config -d CONFIG_CGROUP_BPF
    scripts/config -d CONFIG_BPF_LSM
    scripts/config -d CONFIG_BPF_PRELOAD
    scripts/config -d CONFIG_BPF_LIRC_MODE2
    scripts/config -d CONFIG_BPF_KPROBE_OVERRIDE

    # https://bbs.archlinux.org/viewtopic.php?pid=1824594#p1824594
    scripts/config -e CONFIG_PSI_DEFAULT_DISABLED

    # https://bbs.archlinux.org/viewtopic.php?pid=1863567#p1863567
    scripts/config -d CONFIG_LATENCYTOP
    scripts/config -d CONFIG_SCHED_DEBUG

    # https://bugs.archlinux.org/task/66613
    scripts/config -d CONFIG_KVM_WERROR

    # https://bugs.archlinux.org/task/67614
    scripts/config -d CONFIG_ASHMEM
    scripts/config -d CONFIG_ANDROID

    make olddefconfig
    if [ -f "$HOME/.config/modprobed.db" ]; then
        yes "" | make LSMOD=$HOME/.config/modprobed.db localmodconfig >/dev/null
    fi

    make -s kernelrelease > version
    echo "Prepared $pkgbase version $(<version)"
}

build() {
    cd $_srcname
    make -j$(nproc) all
}

_package() {
    pkgdesc="The $pkgdesc kernel and modules"
    depends=('coreutils' 'kmod' 'initramfs')
    optdepends=('crda: to set the correct wireless channels of your country'
                'linux-firmware: firmware images needed for some devices')
    provides=(VIRTUALBOX-GUEST-MODULES WIREGUARD-MODULE VHBA-MODULE)
    replaces=()

    cd $_srcname
    local kernver="$(<version)"
    local modulesdir="$pkgdir/usr/lib/modules/$kernver"

    echo "Installing boot image..."
    # systemd expects to find the kernel here to allow hibernation
    # https://github.com/systemd/systemd/commit/edda44605f06a41fb86b7ab8128dcf99161d2344
    install -Dm644 "$(make -s image_name)" "$modulesdir/vmlinuz"

    # Used by mkinitcpio to name the kernel
    echo "$pkgbase" | install -Dm644 /dev/stdin "$modulesdir/pkgbase"

    echo "Installing modules..."
    make INSTALL_MOD_PATH="$pkgdir/usr" INSTALL_MOD_STRIP=1 modules_install

    # remove build and source links
    rm "$modulesdir"/{source,build}
}

_package-headers() {
    pkgdesc="Headers and scripts for building modules for the $pkgdesc kernel"
    depends=('pahole')

    cd $_srcname
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
