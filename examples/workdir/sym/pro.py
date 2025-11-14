from pwn import *

if os.path.exists("vmlinux"):
    pass
else:
    os.system("./extract-vmlinux bzImage > vmlinux")

context.log_level = 'debug'

sh = process("./run.sh")
sh.recvuntil("/ $")
sh.sendline("cat addr")
sh.recvuntil("0")
a = sh.recvuntil("/ $")
print(len(a))
#pause()
os.system("touch file")
with open("file", "w") as f:
    f.write("0"+a.decode("iso-8859-1"))

#sh.interactive()


