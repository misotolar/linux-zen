# Zen Kernel Arch Linux package
[![Build Status](https://drone02.sotolar.net/api/badges/misotolar/linux-zen/status.svg)](https://drone02.sotolar.net/misotolar/linux-zen)

Slightly optimized for Lenovo IdeaPad 3 15ADA05-81W1

- Clang Full LTO build
- [PDS Process Scheduler](https://gitlab.com/alfredchen/projectc)
- AMD Zen processor family
- Kernel module signing if [arch-sign-modules](https://aur.archlinux.org/packages/arch-sign-modules) installed
- platform/x86: ideapad-laptop: add support for Ideapad 3 15ADA05-81W1
- [x86/extable: prefer local labels in .set directives](https://github.com/ClangBuiltLinux/linux/issues/1612)
- [tsc: allow directly synchronizing TSC if TSC_ADJUST is absent](https://bugzilla.kernel.org/show_bug.cgi?id=202525)
- XANMOD: block: set rq_affinity to force full multithreading I/O requests
- XANMOD: kconfig: add 500Hz timer interrupt kernel config option
- XANMOD: lib/kconfig.debug: disable default SYMBOLIC_ERRNAME and DEBUG_BUGVERBOSE
- XANMOD: Change rcutree.kthread_prio to SCHED_RR policy
- XANMOD: block/mq-deadline: Disable front_merges by default
- XANMOD: block/mq-deadline: Increase write priority to improve responsiveness
- mac80211: ignore AP power level when tx power type is "fixed"

```
[linux-zen]
SigLevel = Never
Server = https://archlinux.sotolar.net/linux-zen
```