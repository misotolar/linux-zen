# Zen Kernel Arch Linux package
[![Build Status](https://drone02.sotolar.net/api/badges/misotolar/linux-zen/status.svg)](https://drone02.sotolar.net/misotolar/linux-zen)

Slightly optimized for Lenovo IdeaPad 3 15ADA05-81W1

- Clang Thin LTO build
- [PDS Process Scheduler](https://gitlab.com/alfredchen/projectc)
- [Userspace assisted KSM](https://gitlab.com/post-factum/uksmd)
- AMD Zen processor family
- Kernel module signing if [arch-sign-modules](https://aur.archlinux.org/packages/arch-sign-modules) installed
- platform/x86: ideapad-laptop: add support for Ideapad 3 15ADA05-81W1
- [tsc: allow directly synchronizing TSC if TSC_ADJUST is absent](https://bugzilla.kernel.org/show_bug.cgi?id=202525)
- XANMOD: Change rcutree.kthread_prio to SCHED_RR policy
- XANMOD: block/mq-deadline: Disable front_merges by default
- XANMOD: block/mq-deadline: Increase write priority to improve responsiveness
- XANMOD: block: set rq_affinity to force full multithreading I/O requests
- XANMOD: lib/kconfig.debug: disable default SYMBOLIC_ERRNAME and DEBUG_BUGVERBOSE
- XANMOD: kconfig: add 500Hz timer interrupt kernel config option
- mac80211: ignore AP power level when tx power type is "fixed"
- futex-5.19: Add entry point for FUTEX_WAIT_MULTIPLE (opcode 31)

```
[linux-zen]
SigLevel = Never
Server = https://archlinux.sotolar.net/linux-zen
```