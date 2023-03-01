# Zen Kernel Arch Linux package
[![Build Status](https://drone02.sotolar.net/api/badges/misotolar/linux-zen/status.svg)](https://drone02.sotolar.net/misotolar/linux-zen)

Improved Zen Kernel package with [additional patches](https://github.com/sirlucjan/kernel-patches/) and custom config:

- LLVM/LTO build
- [TSC direct sync](https://lore.kernel.org/all/84f991e0-4d14-7ea9-7553-9f688df9cd49@collabora.com/T/#m156fc8ddb3f69691fefedb7bba49a280fe97938e) implementation
- [PDS Process Scheduler](https://gitlab.com/alfredchen/projectc) enabled
- DKMS kernel module signing with [Arch-SKM](https://aur.archlinux.org/packages/arch-sign-modules)
- Linux Random Number Generator
- Futex fixes

```
[linux-zen]
SigLevel = Never
Server = https://archlinux.sotolar.net/linux-zen
```