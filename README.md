# riscv-lld

This repository contains the RISC-V port of lld (the LLVM linker).

## Status

* Can link static ELF executables
* Can link dynamic ELF executables (PIE) and shared libraries
* Thread-local storage (TLS) support
* Can link RISC-V's Linux kernel
* Pass most of GCC testsuite modulo error message differences
* Unit tests

Patches are submitted for review on LLVM phabricator.

**This repository will be regularly rebased onto lld master.**

## How to build

```
$ git clone https://github.com/llvm-mirror/llvm && cd llvm
$ git checkout 1435ef31d8556e5ab90a6ba8c4947da858625d79
$ git clone https://github.com/riscv/riscv-lld tools/lld
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_PROJECTS=lld \
        -DTARGETS_TO_BUILD= \
        -DEXPERIMENTAL_TARGETS_TO_BUILD=RISCV \
        ..
$ make lld
```

## Usage

You may invoke `ld.lld` directly or replace `ld` in the toolchain path with `ld.lld`:

```
$ cp bin/ld.lld ${path_to_toolchain}/bin/ld.lld
$ ln -sf ${path_to_toolchain}/bin/{ld.lld,ld}
```

## Issues

Please report issues related to the RISC-V port on GitHub's issue tracker.
