gcc -fno-stack-protector -o test exp.c --static -masm=intel
cp ./rootfs.cpio.bak  ./rootfs.cpio
echo test | cpio -o --format=newc >> ./rootfs.cpio
