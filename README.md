# Zen Kernel Arch Linux package
[![Build Status](https://drone02.sotolar.net/api/badges/misotolar/linux-zen/status.svg)](https://drone02.sotolar.net/misotolar/linux-zen)

Slightly optimized for Lenovo IdeaPad 3 15ADA05-81W1

- Clang Full LTO build
- [PDS Process Scheduler](https://gitlab.com/alfredchen/projectc)
- AMD Zen processor family
- Ultra-KSM for page merging
- Kernel module signing if [arch-sign-modules](https://aur.archlinux.org/packages/arch-sign-modules) installed
- platform/x86: ideapad-laptop: remove dytc_version check
- [tsc: allow directly synchronizing TSC if TSC_ADJUST is absent](https://bugzilla.kernel.org/show_bug.cgi?id=202525)
- XANMOD: block: set rq_affinity to force full multithreading I/O requests
- XANMOD: kconfig: add 500Hz timer interrupt kernel config option
- XANMOD: lib/kconfig.debug: disable default SYMBOLIC_ERRNAME and DEBUG_BUGVERBOSE
- x86/csum: rewrite/optimize csum_partial()
- tcp: optimizations for linux 5.17
- lib: zstd: upstream updates

```
[linux-zen]
SigLevel = Never
Server = https://archlinux.sotolar.net/linux-zen
```