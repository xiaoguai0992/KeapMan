from pwn import *
sh = process(['gdb', '-ex', 'target remote localhost:1234', '-ex', 'c'])
# 给 GDB 一点时间来初始化
time.sleep(2)

# 发送 SIGINT 信号，模拟按下 Ctrl+C
sh.send_signal(signal.SIGINT)
sh.interactive()