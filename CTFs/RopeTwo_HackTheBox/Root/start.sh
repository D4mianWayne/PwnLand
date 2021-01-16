#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -no-reboot \
    -nographic \
    -kernel ./vmlinuz \
    -append 'console=ttyS0 panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd ./rootfs/initramfs2.cpio  \
    -no-kvm \
    -cpu qemu64,+smep \
    -smp cores=2\
    -gdb tcp::6789
