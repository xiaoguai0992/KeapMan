#!/bin/sh

# Replace with your pandas path
/tmp/panda/build/x86_64-softmmu/panda-system-x86_64 \
-m 512M \
-kernel ./bzImage \
-initrd  ./rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr useradd homura" \
 -monitor telnet:127.0.0.1:5555,server,nowait \
-nographic  \
-device virtio-gpu-pci \
-s 
